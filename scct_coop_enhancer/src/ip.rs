use std::net::{Ipv4Addr, SocketAddr};

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

fn bind_udp_with_fallback(
    bind_ip: Ipv4Addr,
    preferred_port: u16,
    label: &str,
) -> anyhow::Result<std::net::UdpSocket> {
    let primary = SocketAddr::V4(std::net::SocketAddrV4::new(bind_ip, preferred_port));
    match std::net::UdpSocket::bind(primary) {
        Ok(s) => Ok(s),
        Err(_) => {
            let fallback = SocketAddr::V4(std::net::SocketAddrV4::new(bind_ip, 0));
            std::net::UdpSocket::bind(fallback).map_err(|e| {
                anyhow::anyhow!("Failed to bind {} UDP socket on {}: {}", label, bind_ip, e)
            })
        }
    }
}

/// Bind discovery (9100) and gameplay (9103) UDP sockets on `bind_ip` (or `0.0.0.0` when `None`),
/// falling back to an ephemeral port on that same adapter IP if the preferred port is occupied.
pub fn bind_coop_udp_sockets(
    bind_ip: Option<Ipv4Addr>,
) -> anyhow::Result<(std::net::UdpSocket, std::net::UdpSocket)> {
    let ip = bind_ip
        .filter(|a| !a.is_unspecified())
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    let sock_disco = bind_udp_with_fallback(ip, crate::net::DISCOVERY_PORT, "discovery")?;
    let sock_game = bind_udp_with_fallback(ip, crate::net::GAME_PORT, "gameplay")?;
    Ok((sock_disco, sock_game))
}

/// Choose the local LAN IPv4 address to advertise to a co-op peer.
/// Honors an explicit adapter `bind_ip` when set; otherwise picks the best detected local NIC.
pub fn resolve_local_ip_for_coop(
    bind_ip: Option<Ipv4Addr>,
    server_host: &str,
    api_port: u16,
) -> Option<Ipv4Addr> {
    if let Some(ip) = bind_ip.filter(|a| !a.is_unspecified()) {
        return Some(ip);
    }
    use std::net::ToSocketAddrs;
    let target_sa: SocketAddr = format!("{}:{}", server_host, api_port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .unwrap_or_else(|| SocketAddr::from(([8, 8, 8, 8], 80)));
    get_best_local_ip().or_else(|| get_local_ip_to(target_sa))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_local_ip_to() {
        let target: SocketAddr = "8.8.8.8:80".parse().unwrap();
        let local_ip = get_local_ip_to(target);
        assert!(local_ip.is_some());
        let ip = local_ip.unwrap();
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

    #[test]
    fn test_bind_coop_udp_sockets_loopback_and_auto() {
        let (s_disco, s_game) =
            bind_coop_udp_sockets(Some(Ipv4Addr::LOCALHOST)).expect("loopback bind");
        assert_eq!(s_disco.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(s_game.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);

        let (a_disco, a_game) = bind_coop_udp_sockets(None).expect("auto bind");
        assert!(a_disco.local_addr().is_ok());
        assert!(a_game.local_addr().is_ok());
    }

    #[test]
    fn test_resolve_local_ip_for_coop() {
        let forced = Ipv4Addr::new(192, 168, 178, 203);
        assert_eq!(
            resolve_local_ip_for_coop(Some(forced), "127.0.0.1", 8080),
            Some(forced)
        );
        let auto = resolve_local_ip_for_coop(Some(Ipv4Addr::UNSPECIFIED), "8.8.8.8", 80);
        assert!(auto.is_some());
        assert!(!auto.unwrap().is_unspecified());
    }
}
