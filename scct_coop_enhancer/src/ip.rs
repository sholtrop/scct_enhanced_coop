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

/// Query the local IPv4 address that routes towards the given target address.
/// Uses a connected UDP socket to inspect kernel routing without sending network traffic.
pub fn get_local_ip_to(target: SocketAddr) -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect(target).ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// Enumerate all active IPv4 addresses on local adapters.
/// Prioritizes physical network adapters (Ethernet, Wi-Fi) over virtual/VPN adapters.
#[cfg(windows)]
pub fn get_all_local_ips() -> Vec<Ipv4Addr> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut buf_len = 15000u32;
    let mut buf = vec![0u8; buf_len as usize];

    let mut ret = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        )
    };

    if ret == ERROR_BUFFER_OVERFLOW {
        buf.resize(buf_len as usize, 0);
        ret = unsafe {
            GetAdaptersAddresses(
                AF_INET as u32,
                flags,
                null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            )
        };
    }

    if ret != 0 {
        return Vec::new();
    }

    let mut physical_ips = Vec::new();
    let mut virtual_ips = Vec::new();

    let mut curr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !curr.is_null() {
        let adapter = unsafe { &*curr };

        // Check if adapter is up (IfOperStatusUp == 1)
        if adapter.OperStatus == 1 {
            let desc = if !adapter.Description.is_null() {
                let mut len = 0;
                while unsafe { *adapter.Description.add(len) } != 0 {
                    len += 1;
                }
                let slice = unsafe { std::slice::from_raw_parts(adapter.Description, len) };
                String::from_utf16_lossy(slice).to_lowercase()
            } else {
                String::new()
            };

            let friendly = if !adapter.FriendlyName.is_null() {
                let mut len = 0;
                while unsafe { *adapter.FriendlyName.add(len) } != 0 {
                    len += 1;
                }
                let slice = unsafe { std::slice::from_raw_parts(adapter.FriendlyName, len) };
                String::from_utf16_lossy(slice).to_lowercase()
            } else {
                String::new()
            };

            let is_virtual = desc.contains("virtual")
                || desc.contains("hyper-v")
                || desc.contains("vethernet")
                || desc.contains("wsl")
                || desc.contains("vmware")
                || desc.contains("virtualbox")
                || desc.contains("tap")
                || desc.contains("tun")
                || desc.contains("vpn")
                || desc.contains("zerotier")
                || desc.contains("hamachi")
                || desc.contains("tailscale")
                || friendly.contains("virtual")
                || friendly.contains("wsl")
                || friendly.contains("vethernet")
                || friendly.contains("tailscale");

            let mut unicast = adapter.FirstUnicastAddress;
            while !unicast.is_null() {
                let addr = unsafe { &*unicast };
                let sa = addr.Address.lpSockaddr;
                if !sa.is_null() && unsafe { (*sa).sa_family } == AF_INET as u16 {
                    let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                    let ip_be = unsafe { sin.sin_addr.S_un.S_addr };
                    let ip = Ipv4Addr::from(u32::from_be(ip_be));
                    if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
                        if is_virtual {
                            virtual_ips.push(ip);
                        } else {
                            physical_ips.push(ip);
                        }
                    }
                }
                unicast = addr.Next;
            }
        }

        curr = adapter.Next;
    }

    let mut all = physical_ips;
    all.extend(virtual_ips);
    all
}

/// Enumerate all active IPv4 addresses on local adapters (non-Windows fallback).
#[cfg(not(windows))]
pub fn get_all_local_ips() -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    let probes = [
        "8.8.8.8:80",
        "192.168.178.1:80",
        "192.168.1.1:80",
        "192.168.0.1:80",
        "10.0.0.1:80",
    ];
    for p in probes {
        if let Ok(sa) = p.parse()
            && let Some(ip) = get_local_ip_to(sa)
            && !ip.is_loopback()
            && !ip.is_link_local()
            && !ips.contains(&ip)
        {
            ips.push(ip);
        }
    }
    ips
}

/// Return the primary/best physical LAN IPv4 address of the local machine.
pub fn get_best_local_ip() -> Option<Ipv4Addr> {
    let ips = get_all_local_ips();
    // Prefer 192.168.x.x (standard home router subnet)
    for ip in &ips {
        let oct = ip.octets();
        if oct[0] == 192 && oct[1] == 168 {
            return Some(*ip);
        }
    }
    // Then 10.x.x.x
    for ip in &ips {
        let oct = ip.octets();
        if oct[0] == 10 {
            return Some(*ip);
        }
    }
    // Then 172.16.x.x - 172.31.x.x
    for ip in &ips {
        let oct = ip.octets();
        if oct[0] == 172 && (16..=31).contains(&oct[1]) {
            return Some(*ip);
        }
    }
    ips.into_iter().next()
}

/// Find a local IPv4 address that shares the same /24 or /16 subnet as the target IP.
pub fn find_matching_subnet_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let target_oct = target.octets();
    let ips = get_all_local_ips();

    // 1. Exact /24 match (e.g. 192.168.178.x)
    for ip in &ips {
        let oct = ip.octets();
        if oct[0] == target_oct[0] && oct[1] == target_oct[1] && oct[2] == target_oct[2] {
            return Some(*ip);
        }
    }

    // 2. /16 match (e.g. 192.168.x.x)
    for ip in &ips {
        let oct = ip.octets();
        if oct[0] == target_oct[0] && oct[1] == target_oct[1] {
            return Some(*ip);
        }
    }

    None
}

/// Check if two IPv4 addresses share the same /24 subnet.
pub fn is_same_subnet(ip1: Ipv4Addr, ip2: Ipv4Addr) -> bool {
    let o1 = ip1.octets();
    let o2 = ip2.octets();
    o1[0] == o2[0] && o1[1] == o2[1] && o1[2] == o2[2]
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
    fn test_get_local_ip_to() {
        let target: SocketAddr = "8.8.8.8:80".parse().unwrap();
        let local_ip = get_local_ip_to(target);
        assert!(local_ip.is_some());
        let ip = local_ip.unwrap();
        assert!(!ip.is_unspecified());
    }

    #[test]
    fn test_fetch_public_ip_live() {
        let res = fetch_public_ip();
        assert!(res.is_ok(), "Failed to fetch public IP: {:?}", res.err());
        let ip = res.unwrap();
        assert!(!ip.is_loopback());
        assert!(!ip.is_unspecified());
    }

    #[test]
    fn test_subnet_matching() {
        let ip1 = Ipv4Addr::new(192, 168, 178, 202);
        let ip2 = Ipv4Addr::new(192, 168, 178, 55);
        let ip3 = Ipv4Addr::new(10, 183, 216, 103);
        let ip4 = Ipv4Addr::new(172, 30, 204, 132);

        assert!(is_same_subnet(ip1, ip2));
        assert!(!is_same_subnet(ip1, ip3));
        assert!(!is_same_subnet(ip1, ip4));
        assert!(!is_same_subnet(ip3, ip4));
    }

    #[test]
    fn test_get_best_local_ip() {
        let best = get_best_local_ip();
        assert!(best.is_some());
        let ip = best.unwrap();
        assert!(!ip.is_loopback());
        assert!(!ip.is_unspecified());
    }
}
