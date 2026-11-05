use anyhow::{bail, Context, Result};
use igd_next::{search_gateway, PortMappingProtocol, SearchOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct UpnpStatus {
    pub gateway_ip: Option<IpAddr>,
    pub public_ip: Option<Ipv4Addr>,
    pub ports_forwarded: bool,
    pub is_cgnat: bool,
    pub message: String,
}

pub fn get_local_lan_ip() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) => Some(*addr.ip()),
        _ => None,
    }
}

pub fn is_cgnat(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

pub fn fetch_public_ip_http() -> Result<Ipv4Addr> {
    let endpoints = [
        ("api.ipify.org", 80),
        ("api4.ipify.org", 80),
        ("icanhazip.com", 80),
    ];

    for &(host, port) in &endpoints {
        if let Ok(ip) = fetch_ip_from_endpoint(host, port) {
            return Ok(ip);
        }
    }
    bail!("Failed to retrieve public IP via HTTP fallback services")
}

fn fetch_ip_from_endpoint(host: &str, port: u16) -> Result<Ipv4Addr> {
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
        "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: SCCT-Patcher\r\nConnection: close\r\n\r\n",
        host
    );
    stream.write_all(req.as_bytes())?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);

    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .context("Malformed HTTP response")?;
    let ip: Ipv4Addr = body.trim().parse()?;
    Ok(ip)
}

pub fn open_coop_ports() -> Result<UpnpStatus> {
    let local_ip = match get_local_lan_ip() {
        Some(ip) => ip,
        None => bail!("Unable to detect local network adapter IP"),
    };

    let mut search_opts = SearchOptions::default();
    search_opts.timeout = Some(Duration::from_secs(3));

    let (gateway, gw_ip) = match search_gateway(search_opts) {
        Ok(gw) => {
            let ip = gw.addr.ip();
            (Some(gw), Some(ip))
        }
        Err(e) => {
            let http_ip = fetch_public_ip_http().ok();
            return Ok(UpnpStatus {
                gateway_ip: None,
                public_ip: http_ip,
                ports_forwarded: false,
                is_cgnat: http_ip.as_ref().is_some_and(is_cgnat),
                message: format!(
                    "UPnP not found or disabled on router ({:#}). Please enable UPnP in your router settings or forward UDP ports 9100 and 9103 manually.",
                    e
                ),
            });
        }
    };

    let gw = gateway.unwrap();

    let external_ip = match gw.get_external_ip() {
        Ok(IpAddr::V4(v4)) => Some(v4),
        _ => fetch_public_ip_http().ok(),
    };

    let local_9100 = SocketAddrV4::new(local_ip, 9100);
    gw.add_port(
        PortMappingProtocol::UDP,
        9100,
        SocketAddr::V4(local_9100),
        7200,
        "SCCT Coop Discovery (UDP 9100)",
    )
    .context("Failed to forward UDP 9100 via UPnP")?;

    let local_9103 = SocketAddrV4::new(local_ip, 9103);
    gw.add_port(
        PortMappingProtocol::UDP,
        9103,
        SocketAddr::V4(local_9103),
        7200,
        "SCCT Coop PRUDP (UDP 9103)",
    )
    .context("Failed to forward UDP 9103 via UPnP")?;

    let cgnat = external_ip.as_ref().is_some_and(is_cgnat);

    let msg = if cgnat {
        "Warning: Carrier-Grade NAT (CGNAT) detected. Inbound traffic may be blocked by your ISP."
            .to_string()
    } else {
        format!(
            "UPnP active on gateway {}: UDP 9100 & 9103 forwarded successfully to local IP {}.",
            gw_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            local_ip
        )
    };

    Ok(UpnpStatus {
        gateway_ip: gw_ip,
        public_ip: external_ip,
        ports_forwarded: true,
        is_cgnat: cgnat,
        message: msg,
    })
}
