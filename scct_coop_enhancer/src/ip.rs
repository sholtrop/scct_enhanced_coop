use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Parse IPv4 from JSON `{"ip":"x.x.x.x"}` or plain text response
pub fn parse_ip_response(text: &str) -> Option<Ipv4Addr> {
    // 1. Try parsing JSON format: {"ip":"x.x.x.x"}
    if let Some(pos) = text.find("\"ip\"") {
        let after = &text[pos + 4..];
        if let Some(start) = after.find('"') {
            let rest = &after[start + 1..];
            if let Some(end) = rest.find('"')
                && let Ok(ip) = rest[..end].trim().parse::<Ipv4Addr>()
            {
                return Some(ip);
            }
        }
    }

    // 2. Fallback: try parsing any line containing a valid IPv4 address
    for line in text.lines() {
        let trimmed = line.trim();
        if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
            return Some(ip);
        }
    }

    None
}

/// Fetch public IPv4 address using api.ipify.org with fallbacks
pub fn fetch_public_ip() -> Result<Ipv4Addr> {
    let endpoints = [
        ("api.ipify.org", 80, "/?format=json"),
        ("api4.ipify.org", 80, "/?format=json"),
        ("icanhazip.com", 80, "/"),
    ];

    for &(host, port, path) in &endpoints {
        if let Ok(ip) = fetch_ip_from_endpoint(host, port, path) {
            return Ok(ip);
        }
    }
    bail!("Failed to retrieve public IP from external services. Check your Internet connection.")
}

fn fetch_ip_from_endpoint(host: &str, port: u16, path: &str) -> Result<Ipv4Addr> {
    let addrs: Vec<SocketAddr> = format!("{}:{}", host, port)
        .to_socket_addrs()?
        .collect();
    if addrs.is_empty() {
        bail!("Could not resolve {}", host);
    }

    let mut stream = TcpStream::connect_timeout(&addrs[0], Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: SCCT-Patcher\r\nConnection: close\r\n\r\n",
        path, host
    );
    stream.write_all(req.as_bytes())?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);

    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .context("Malformed HTTP response")?;

    parse_ip_response(body).context("Could not parse IP from response body")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_json() {
        let json = r#"{"ip":"80.115.168.197"}"#;
        assert_eq!(
            parse_ip_response(json),
            Some(Ipv4Addr::new(80, 115, 168, 197))
        );

        let json_spaced = r#"{ "ip" : "192.168.1.50" }"#;
        assert_eq!(
            parse_ip_response(json_spaced),
            Some(Ipv4Addr::new(192, 168, 1, 50))
        );
    }

    #[test]
    fn test_parse_ip_plain() {
        let plain = "80.115.168.197\n";
        assert_eq!(
            parse_ip_response(plain),
            Some(Ipv4Addr::new(80, 115, 168, 197))
        );
    }

    #[test]
    fn test_fetch_public_ip_live() {
        let res = fetch_public_ip();
        assert!(res.is_ok(), "Failed to fetch public IP: {:?}", res.err());
        let ip = res.unwrap();
        assert!(!ip.is_loopback());
        assert!(!ip.is_unspecified());
    }
}
