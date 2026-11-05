use rand::{rng, RngCore};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const HEADER_SIZE: usize = 20;

pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_SOFTWARE: u16 = 0x8022;

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;
const CLASS_MASK: u8 = 0x07;

#[derive(Error, Debug)]
pub enum StunError {
    #[error("Invalid STUN message: {0}")]
    InvalidMsg(String),
    #[error("No mapped address found in response")]
    NoMappedAddress,
    #[error("Transaction ID mismatch")]
    TransactionMismatch,
    #[error("STUN request timed out")]
    Timeout,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StunError>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TransactionId(pub [u8; 12]);

#[allow(dead_code)]
impl TransactionId {
    pub fn random() -> Self {
        let mut b = [0u8; 12];
        rng().fill_bytes(&mut b);
        Self(b)
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageType {
    BindingRequest,
    BindingResponse,
    BindingError,
}

impl From<MessageType> for u16 {
    fn from(t: MessageType) -> u16 {
        match t {
            MessageType::BindingRequest => 0x0001,
            MessageType::BindingResponse => 0x0101,
            MessageType::BindingError => 0x0111,
        }
    }
}

impl TryFrom<u16> for MessageType {
    type Error = StunError;

    fn try_from(v: u16) -> Result<Self> {
        match v {
            0x0001 => Ok(MessageType::BindingRequest),
            0x0101 => Ok(MessageType::BindingResponse),
            0x0111 => Ok(MessageType::BindingError),
            t => Err(StunError::InvalidMsg(format!(
                "Unsupported message type {t:#06x}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attribute {
    MappedAddress(SocketAddr),
    XorMappedAddress(SocketAddr),
    ErrorCode { code: u16, reason: String },
    Software(String),
    Unknown { attr_type: u16, value: Vec<u8> },
}

impl Attribute {
    pub fn encode(&self, txn_id: &TransactionId, dst: &mut Vec<u8>) -> Result<()> {
        let (attr_type, value) = match self {
            Attribute::MappedAddress(sa) => (ATTR_MAPPED_ADDRESS, encode_address(sa)),
            Attribute::XorMappedAddress(sa) => (
                ATTR_XOR_MAPPED_ADDRESS,
                encode_address(&xor_address(sa, txn_id)),
            ),
            Attribute::ErrorCode { code, reason } => (ATTR_ERROR_CODE, encode_error(*code, reason)),
            Attribute::Software(s) => (ATTR_SOFTWARE, s.as_bytes().to_vec()),
            Attribute::Unknown { attr_type, value } => (*attr_type, value.clone()),
        };

        if value.len() > u16::MAX as usize {
            return Err(StunError::InvalidMsg("Attribute value too large".into()));
        }

        dst.extend_from_slice(&attr_type.to_be_bytes());
        dst.extend_from_slice(&(value.len() as u16).to_be_bytes());
        dst.extend_from_slice(&value);
        for _ in 0..(4 - value.len() % 4) % 4 {
            dst.push(0);
        }
        Ok(())
    }

    pub fn decode(txn_id: &TransactionId, src: &[u8]) -> Result<Option<(usize, Self)>> {
        if src.len() < 4 {
            return Ok(None);
        }
        let attr_type = u16::from_be_bytes([src[0], src[1]]);
        let len = u16::from_be_bytes([src[2], src[3]]) as usize;
        let padded = (len + 3) & !3;
        if src.len() < 4 + padded {
            return Ok(None);
        }
        let value = &src[4..4 + len];

        let attr = match attr_type {
            ATTR_MAPPED_ADDRESS => Attribute::MappedAddress(decode_address(value)?),
            ATTR_XOR_MAPPED_ADDRESS => {
                Attribute::XorMappedAddress(xor_address(&decode_address(value)?, txn_id))
            }
            ATTR_ERROR_CODE => decode_error(value)?,
            ATTR_SOFTWARE => Attribute::Software(String::from_utf8_lossy(value).into_owned()),
            t => Attribute::Unknown {
                attr_type: t,
                value: value.to_vec(),
            },
        };
        Ok(Some((4 + padded, attr)))
    }
}

pub fn xor_address(sa: &SocketAddr, txn_id: &TransactionId) -> SocketAddr {
    let port = sa.port() ^ (MAGIC_COOKIE >> 16) as u16;
    let ip = match sa.ip() {
        IpAddr::V4(v4) => {
            let mut o = v4.octets();
            for (b, k) in o.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
                *b ^= k;
            }
            IpAddr::V4(Ipv4Addr::from(o))
        }
        IpAddr::V6(v6) => {
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(&txn_id.0);
            let mut o = v6.octets();
            for (b, k) in o.iter_mut().zip(key) {
                *b ^= k;
            }
            IpAddr::V6(Ipv6Addr::from(o))
        }
    };
    SocketAddr::new(ip, port)
}

fn encode_address(sa: &SocketAddr) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.push(0);
    match sa.ip() {
        IpAddr::V4(ip) => {
            v.push(FAMILY_IPV4);
            v.extend_from_slice(&sa.port().to_be_bytes());
            v.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            v.push(FAMILY_IPV6);
            v.extend_from_slice(&sa.port().to_be_bytes());
            v.extend_from_slice(&ip.octets());
        }
    }
    v
}

fn decode_address(value: &[u8]) -> Result<SocketAddr> {
    if value.len() < 4 {
        return Err(StunError::InvalidMsg("Address attribute too short".into()));
    }
    let port = u16::from_be_bytes([value[2], value[3]]);
    let ip = match value[1] {
        FAMILY_IPV4 if value.len() == 8 => {
            let o: [u8; 4] = value[4..8].try_into().map_err(|_| StunError::InvalidMsg("Length mismatch".into()))?;
            IpAddr::V4(Ipv4Addr::from(o))
        }
        FAMILY_IPV6 if value.len() == 20 => {
            let o: [u8; 16] = value[4..20].try_into().map_err(|_| StunError::InvalidMsg("Length mismatch".into()))?;
            IpAddr::V6(Ipv6Addr::from(o))
        }
        _ => return Err(StunError::InvalidMsg("Bad address family or length".into())),
    };
    Ok(SocketAddr::new(ip, port))
}

fn encode_error(code: u16, reason: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + reason.len());
    let class = (code / 100) as u8 & CLASS_MASK;
    v.extend_from_slice(&[0, 0, class, (code % 100) as u8]);
    v.extend_from_slice(reason.as_bytes());
    v
}

fn decode_error(value: &[u8]) -> Result<Attribute> {
    if value.len() < 4 {
        return Err(StunError::InvalidMsg("Error attribute too short".into()));
    }
    let code = (value[2] & CLASS_MASK) as u16 * 100 + value[3] as u16;
    let reason = String::from_utf8_lossy(&value[4..]).into_owned();
    Ok(Attribute::ErrorCode { code, reason })
}

#[derive(Clone, Debug)]
pub struct StunMessage {
    pub msg_type: MessageType,
    pub txn_id: TransactionId,
    pub attrs: Vec<Attribute>,
}

impl StunMessage {
    #[allow(dead_code)]
    pub fn binding_request() -> Self {
        Self {
            msg_type: MessageType::BindingRequest,
            txn_id: TransactionId::random(),
            attrs: vec![],
        }
    }

    pub fn binding_response(request: &StunMessage, source: SocketAddr) -> Self {
        Self {
            msg_type: MessageType::BindingResponse,
            txn_id: request.txn_id,
            attrs: vec![Attribute::XorMappedAddress(source)],
        }
    }

    #[allow(dead_code)]
    pub fn mapped_address(&self) -> Result<SocketAddr> {
        for attr in &self.attrs {
            if let Attribute::XorMappedAddress(sa) = attr {
                return Ok(*sa);
            }
        }
        for attr in &self.attrs {
            if let Attribute::MappedAddress(sa) = attr {
                return Ok(*sa);
            }
        }
        Err(StunError::NoMappedAddress)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        for attr in &self.attrs {
            attr.encode(&self.txn_id, &mut body)?;
        }
        if body.len() > u16::MAX as usize {
            return Err(StunError::InvalidMsg("Message too large".into()));
        }

        let mut out = Vec::with_capacity(HEADER_SIZE + body.len());
        out.extend_from_slice(&u16::from(self.msg_type).to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&self.txn_id.0);
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn decode(src: &[u8]) -> Result<Option<(usize, Self)>> {
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        let raw_type = u16::from_be_bytes([src[0], src[1]]);
        if raw_type & 0xC000 != 0 {
            return Err(StunError::InvalidMsg("Top two bits not zero".into()));
        }
        let length = u16::from_be_bytes([src[2], src[3]]) as usize;
        if !length.is_multiple_of(4) {
            return Err(StunError::InvalidMsg("Length not 4-byte aligned".into()));
        }
        let cookie = u32::from_be_bytes([src[4], src[5], src[6], src[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(StunError::InvalidMsg("Bad magic cookie".into()));
        }
        if src.len() < HEADER_SIZE + length {
            return Ok(None);
        }

        let msg_type = MessageType::try_from(raw_type)?;
        let mut txn = [0u8; 12];
        txn.copy_from_slice(&src[8..HEADER_SIZE]);
        let txn_id = TransactionId(txn);

        let mut attrs = Vec::new();
        let mut off = HEADER_SIZE;
        let end = HEADER_SIZE + length;
        while off < end {
            match Attribute::decode(&txn_id, &src[off..end])? {
                Some((n, attr)) => {
                    attrs.push(attr);
                    off += n;
                }
                None => return Err(StunError::InvalidMsg("Truncated attribute".into())),
            }
        }

        Ok(Some((
            end,
            Self {
                msg_type,
                txn_id,
                attrs,
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_roundtrip() {
        let request = StunMessage::binding_request();
        let bytes = request.encode().unwrap();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let (n, decoded) = StunMessage::decode(&bytes).unwrap().unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(decoded.msg_type, MessageType::BindingRequest);
        assert_eq!(decoded.txn_id, request.txn_id);

        let source: SocketAddr = "82.165.45.112:54210".parse().unwrap();
        let resp = StunMessage::binding_response(&request, source);
        let resp_bytes = resp.encode().unwrap();

        let (_, decoded_resp) = StunMessage::decode(&resp_bytes).unwrap().unwrap();
        assert_eq!(decoded_resp.msg_type, MessageType::BindingResponse);
        assert_eq!(decoded_resp.mapped_address().unwrap(), source);
    }
}
