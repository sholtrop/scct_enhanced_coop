use anyhow::{Context, Result, bail};
use rand::{rng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

pub const DEFAULT_SERVER_HOST: &str = "scct_coop.sholtrop.dev";
pub const DEFAULT_STUN_PORT: u16 = 3478;
pub const DEFAULT_API_PORT: u16 = 8080;

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const HEADER_SIZE: usize = 20;

pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

pub const CROCKFORD_CHARS: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn generate_friend_code() -> String {
    let mut code = String::with_capacity(5);
    let mut r = rng();
    for _ in 0..5 {
        let idx = r.random_range(0..CROCKFORD_CHARS.len());
        code.push(CROCKFORD_CHARS[idx] as char);
    }
    code
}

pub fn normalize_friend_code(input: &str) -> String {
    input
        .trim()
        .to_ascii_uppercase()
        .chars()
        .filter_map(|c| match c {
            'O' => Some('0'),
            'I' | 'L' => Some('1'),
            c if CROCKFORD_CHARS.contains(&(c as u8)) => Some(c),
            _ => None,
        })
        .take(5)
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TransactionId(pub [u8; 12]);

impl TransactionId {
    pub fn random() -> Self {
        let mut b = [0u8; 12];
        rng().fill_bytes(&mut b);
        Self(b)
    }
}

pub struct StunMessage {
    pub txn_id: TransactionId,
}

impl StunMessage {
    pub fn build_binding_request() -> (TransactionId, Vec<u8>) {
        let txn_id = TransactionId::random();
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
        out.extend_from_slice(&0u16.to_be_bytes());     // Length = 0
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&txn_id.0);
        (txn_id, out)
    }

    pub fn parse_binding_response(src: &[u8], expected_txn: &TransactionId) -> Result<SocketAddr> {
        if src.len() < HEADER_SIZE {
            bail!("STUN response too short");
        }

        let raw_type = u16::from_be_bytes([src[0], src[1]]);
        if raw_type != 0x0101 {
            bail!("Not a Binding Response (type: 0x{:04x})", raw_type);
        }

        let cookie = u32::from_be_bytes([src[4], src[5], src[6], src[7]]);
        if cookie != MAGIC_COOKIE {
            bail!("Invalid STUN magic cookie");
        }

        if src[8..HEADER_SIZE] != expected_txn.0 {
            bail!("STUN transaction ID mismatch");
        }

        let length = u16::from_be_bytes([src[2], src[3]]) as usize;
        let mut off = HEADER_SIZE;
        let end = (HEADER_SIZE + length).min(src.len());

        let mut xor_addr = None;
        let mut mapped_addr = None;

        while off + 4 <= end {
            let attr_type = u16::from_be_bytes([src[off], src[off + 1]]);
            let attr_len = u16::from_be_bytes([src[off + 2], src[off + 3]]) as usize;
            let val_start = off + 4;
            let val_end = (val_start + attr_len).min(end);
            let val = &src[val_start..val_end];

            if attr_type == ATTR_XOR_MAPPED_ADDRESS && val.len() >= 4 {
                if let Ok(sa) = decode_xor_address(val, expected_txn) {
                    xor_addr = Some(sa);
                }
            } else if attr_type == ATTR_MAPPED_ADDRESS
                && val.len() >= 4
                && let Ok(sa) = decode_raw_address(val)
            {
                mapped_addr = Some(sa);
            }

            let padded_len = (attr_len + 3) & !3;
            off += 4 + padded_len;
        }

        xor_addr
            .or(mapped_addr)
            .context("No mapped address in STUN response")
    }
}

fn decode_raw_address(val: &[u8]) -> Result<SocketAddr> {
    let port = u16::from_be_bytes([val[2], val[3]]);
    match val[1] {
        0x01 if val.len() >= 8 => {
            let octets: [u8; 4] = val[4..8].try_into()?;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 if val.len() >= 20 => {
            let octets: [u8; 16] = val[4..20].try_into()?;
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => bail!("Unsupported address family"),
    }
}

fn decode_xor_address(val: &[u8], txn_id: &TransactionId) -> Result<SocketAddr> {
    let raw_port = u16::from_be_bytes([val[2], val[3]]);
    let port = raw_port ^ (MAGIC_COOKIE >> 16) as u16;

    match val[1] {
        0x01 if val.len() >= 8 => {
            let mut octets: [u8; 4] = val[4..8].try_into()?;
            for (b, k) in octets.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
                *b ^= k;
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 if val.len() >= 20 => {
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(&txn_id.0);
            let mut octets: [u8; 16] = val[4..20].try_into()?;
            for (b, k) in octets.iter_mut().zip(key) {
                *b ^= k;
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => bail!("Unsupported address family"),
    }
}

pub fn stun_query(socket: &UdpSocket, server_host: &str, stun_port: u16) -> Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = format!("{}:{}", server_host, stun_port)
        .to_socket_addrs()
        .with_context(|| format!("Resolving STUN server {}:{}", server_host, stun_port))?
        .collect();

    if addrs.is_empty() {
        bail!("Could not resolve STUN server {}:{}", server_host, stun_port);
    }

    let target = addrs[0];
    let (txn_id, req_bytes) = StunMessage::build_binding_request();

    socket.set_read_timeout(Some(Duration::from_millis(1500)))?;
    socket.set_write_timeout(Some(Duration::from_millis(1500)))?;

    for _ in 0..3 {
        let _ = socket.send_to(&req_bytes, target);

        let mut buf = [0u8; 1500];
        if let Ok((n, from)) = socket.recv_from(&mut buf)
            && (from == target || from.ip() == target.ip())
            && let Ok(mapped) = StunMessage::parse_binding_response(&buf[..n], &txn_id)
        {
            return Ok(mapped);
        }
    }

    bail!("STUN discovery timed out contacting {}", target)
}

#[derive(Serialize)]
struct ApiRegisterReq {
    friend_code: Option<String>,
    disco_addr: SocketAddr,
    game_addr: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_ip: Option<Ipv4Addr>,
}

#[derive(Deserialize)]
struct ApiRegisterResp {
    friend_code: String,
}

#[derive(Serialize)]
struct ApiJoinReq {
    friend_code: String,
    disco_addr: SocketAddr,
    game_addr: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_ip: Option<Ipv4Addr>,
}

#[derive(Deserialize)]
struct ApiJoinResp {
    status: String,
    peer_disco_addr: Option<SocketAddr>,
    peer_game_addr: Option<SocketAddr>,
    #[serde(default)]
    peer_local_ip: Option<Ipv4Addr>,
}

#[derive(Deserialize)]
struct ApiPollResp {
    status: String,
    peer_disco_addr: Option<SocketAddr>,
    peer_game_addr: Option<SocketAddr>,
    #[serde(default)]
    peer_local_ip: Option<Ipv4Addr>,
}

fn http_post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
    server_host: &str,
    api_port: u16,
    path: &str,
    payload: &T,
) -> Result<R> {
    let addrs: Vec<SocketAddr> = format!("{}:{}", server_host, api_port)
        .to_socket_addrs()
        .with_context(|| format!("Resolving API server {}:{}", server_host, api_port))?
        .collect();

    if addrs.is_empty() {
        bail!("Could not resolve {}:{}", server_host, api_port);
    }

    let body = serde_json::to_string(payload)?;
    let mut stream = TcpStream::connect_timeout(&addrs[0], Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, server_host, body.len(), body
    );
    stream.write_all(req.as_bytes())?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp)?;
    let text = String::from_utf8_lossy(&resp);

    let json_body = text.split("\r\n\r\n").nth(1).context("Malformed HTTP response")?;
    let res: R = serde_json::from_str(json_body)
        .with_context(|| format!("Failed to parse response: {}", json_body))?;
    Ok(res)
}

fn http_get_json<R: for<'de> Deserialize<'de>>(
    server_host: &str,
    api_port: u16,
    path: &str,
) -> Result<R> {
    let addrs: Vec<SocketAddr> = format!("{}:{}", server_host, api_port)
        .to_socket_addrs()
        .with_context(|| format!("Resolving API server {}:{}", server_host, api_port))?
        .collect();

    if addrs.is_empty() {
        bail!("Could not resolve {}:{}", server_host, api_port);
    }

    let mut stream = TcpStream::connect_timeout(&addrs[0], Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, server_host
    );
    stream.write_all(req.as_bytes())?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp)?;
    let text = String::from_utf8_lossy(&resp);

    let json_body = text.split("\r\n\r\n").nth(1).context("Malformed HTTP response")?;
    let res: R = serde_json::from_str(json_body)
        .with_context(|| format!("Failed to parse response: {}", json_body))?;
    Ok(res)
}

pub fn register_with_server(
    server_host: &str,
    api_port: u16,
    friend_code: Option<String>,
    disco_addr: SocketAddr,
    game_addr: SocketAddr,
    local_ip: Option<Ipv4Addr>,
) -> Result<String> {
    let req = ApiRegisterReq {
        friend_code,
        disco_addr,
        game_addr,
        local_ip,
    };
    let resp: ApiRegisterResp = http_post_json(server_host, api_port, "/api/register", &req)?;
    Ok(resp.friend_code)
}

pub fn join_with_server(
    server_host: &str,
    api_port: u16,
    friend_code: &str,
    disco_addr: SocketAddr,
    game_addr: SocketAddr,
    local_ip: Option<Ipv4Addr>,
) -> Result<(SocketAddr, SocketAddr, Option<Ipv4Addr>)> {
    let req = ApiJoinReq {
        friend_code: friend_code.to_string(),
        disco_addr,
        game_addr,
        local_ip,
    };
    let resp: ApiJoinResp = http_post_json(server_host, api_port, "/api/join", &req)?;
    if resp.status == "paired"
        && let Some(disco) = resp.peer_disco_addr
        && let Some(game) = resp.peer_game_addr
    {
        Ok((disco, game, resp.peer_local_ip))
    } else {
        bail!("Friend code '{}' not found or invalid", friend_code)
    }
}

pub fn poll_server_for_peer(
    server_host: &str,
    api_port: u16,
    friend_code: &str,
) -> Result<Option<(SocketAddr, SocketAddr, Option<Ipv4Addr>)>> {
    let path = format!("/api/poll/{}", friend_code);
    let resp: ApiPollResp = http_get_json(server_host, api_port, &path)?;
    if resp.status == "paired"
        && let Some(disco) = resp.peer_disco_addr
        && let Some(game) = resp.peer_game_addr
    {
        Ok(Some((disco, game, resp.peer_local_ip)))
    } else {
        Ok(None)
    }
}

pub fn punch_udp_holes(
    sock_disco: &UdpSocket,
    sock_game: &UdpSocket,
    peer_disco: SocketAddr,
    peer_game: SocketAddr,
) {
    let punch_payload = b"SCCT_PUNCH_V1";
    for _ in 0..5 {
        let _ = sock_disco.send_to(punch_payload, peer_disco);
        let _ = sock_game.send_to(punch_payload, peer_game);
        std::thread::sleep(Duration::from_millis(80));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_friend_code_generator() {
        let code = generate_friend_code();
        assert_eq!(code.len(), 5);
        for b in code.bytes() {
            assert!(CROCKFORD_CHARS.contains(&b));
        }
    }

    #[test]
    fn test_normalize_code() {
        assert_eq!(normalize_friend_code("k7x9b"), "K7X9B");
        assert_eq!(normalize_friend_code("o1li"), "0111");
    }

    #[test]
    fn test_stun_req_resp_parsing() {
        let (txn, req) = StunMessage::build_binding_request();
        assert_eq!(req.len(), HEADER_SIZE);

        let mut resp = Vec::new();
        resp.extend_from_slice(&0x0101u16.to_be_bytes()); // Binding Response
        resp.extend_from_slice(&12u16.to_be_bytes());     // Length = 12
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn.0);

        // Append XOR-MAPPED-ADDRESS: 82.165.45.112:54210
        let target: SocketAddr = "82.165.45.112:54210".parse().unwrap();
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.push(0);
        resp.push(0x01); // IPv4
        let raw_port = target.port() ^ (MAGIC_COOKIE >> 16) as u16;
        resp.extend_from_slice(&raw_port.to_be_bytes());
        if let IpAddr::V4(v4) = target.ip() {
            let mut o = v4.octets();
            for (b, k) in o.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
                *b ^= k;
            }
            resp.extend_from_slice(&o);
        }

        let parsed = StunMessage::parse_binding_response(&resp, &txn).unwrap();
        assert_eq!(parsed, target);
    }
}
