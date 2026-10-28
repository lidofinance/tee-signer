//! Test helpers: a small deterministic PRNG and the server side of NTS-KE and
//! of NTS-protected NTP. The server side is written here from the RFC, apart
//! from the client code in the crate, and calls `aes-siv` directly, so the
//! two sides check each other.

#![allow(dead_code)]

use aes_siv::KeyInit;
use aes_siv::aead::generic_array::GenericArray;
use aes_siv::siv::Aes128Siv;

/// splitmix64. The same seed gives the same sequence on every run.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in 0..n, n > 0.
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

// ---- NTS-KE, server side (RFC 8915 section 4) ----

/// One record: critical bit and type, body length, body.
pub fn record(critical: bool, record_type: u16, body: &[u8]) -> Vec<u8> {
    let t = if critical { record_type | 0x8000 } else { record_type };
    let mut v = t.to_be_bytes().to_vec();
    v.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    v.extend_from_slice(body);
    v
}

pub fn end_of_message() -> Vec<u8> {
    record(true, 0, &[])
}

/// The records of a good response, without End of Message: next protocol
/// NTPv4, AEAD 15, then the cookies.
pub fn good_ke_records(cookies: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut r = vec![record(true, 1, &[0, 0]), record(true, 4, &[0, 15])];
    for c in cookies {
        r.push(record(false, 5, c));
    }
    r
}

pub fn eight_cookies() -> Vec<Vec<u8>> {
    (0..8u8).map(|i| vec![i + 1; 100]).collect()
}

/// A good response with eight 100-octet cookies.
pub fn good_ke_response() -> Vec<u8> {
    let mut r = good_ke_records(&eight_cookies());
    r.push(end_of_message());
    r.concat()
}

/// The records of a message, as (critical, type, body). Panics if malformed.
pub fn split_records(mut buf: &[u8]) -> Vec<(bool, u16, Vec<u8>)> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let t = u16::from_be_bytes([buf[0], buf[1]]);
        let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        out.push((t & 0x8000 != 0, t & 0x7fff, buf[4..4 + len].to_vec()));
        buf = &buf[4 + len..];
    }
    out
}

// ---- NTP with NTS, server side (RFC 8915 section 5, RFC 5905 section 7.3) ----

/// Test keys (not secret).
pub const C2S: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];
pub const S2C: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];

/// AES-SIV-CMAC-256 with S2V over (associated data, nonce), then the plaintext.
pub fn seal(key: &[u8; 32], ad: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    Aes128Siv::new(GenericArray::from_slice(key)).encrypt([ad, nonce], plaintext).unwrap()
}

pub fn open(key: &[u8; 32], ad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    Aes128Siv::new(GenericArray::from_slice(key)).decrypt([ad, nonce], ciphertext).ok()
}

fn padded(b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    v.resize(b.len().div_ceil(4) * 4, 0);
    v
}

/// An extension field (RFC 7822 section 7.5): type, whole length, body, zero padding.
pub fn field(field_type: u16, body: &[u8]) -> Vec<u8> {
    let body = padded(body);
    let mut v = field_type.to_be_bytes().to_vec();
    v.extend_from_slice(&u16::try_from(4 + body.len()).unwrap().to_be_bytes());
    v.extend_from_slice(&body);
    v
}

/// What a server reads from a client request.
#[derive(Clone, Debug)]
pub struct ClientRequest {
    pub transmit: [u8; 8],
    pub unique_id: Vec<u8>,
    pub cookie: Vec<u8>,
    pub placeholders: usize,
    pub placeholder_len: usize,
}

/// Reads a client request the way a server would and checks the
/// authenticator with `c2s`. `None` if anything is wrong.
pub fn server_read_request(c2s: &[u8; 32], packet: &[u8]) -> Option<ClientRequest> {
    if packet.len() < 48 || packet[0] & 0x3f != (4 << 3) | 3 {
        return None;
    }
    let transmit: [u8; 8] = packet[40..48].try_into().ok()?;
    let (mut unique_id, mut cookie) = (None, None);
    let (mut placeholders, mut placeholder_len) = (0, 0);
    let mut at = 48;
    while at < packet.len() {
        let t = u16::from_be_bytes(packet.get(at..at + 2)?.try_into().ok()?);
        let len = usize::from(u16::from_be_bytes(packet.get(at + 2..at + 4)?.try_into().ok()?));
        if len < 16 || len % 4 != 0 {
            return None;
        }
        let body = packet.get(at + 4..at + len)?;
        match t {
            0x0104 => unique_id = Some(body.to_vec()),
            0x0204 => cookie = Some(body.to_vec()),
            0x0304 => {
                placeholders += 1;
                placeholder_len = body.len();
            }
            0x0404 => {
                let nonce_len = usize::from(u16::from_be_bytes(body[0..2].try_into().ok()?));
                let ct_len = usize::from(u16::from_be_bytes(body[2..4].try_into().ok()?));
                let nonce = body.get(4..4 + nonce_len)?;
                let ct_at = 4 + nonce_len.div_ceil(4) * 4;
                let ct = body.get(ct_at..ct_at + ct_len)?;
                let plaintext = open(c2s, &packet[..at], nonce, ct)?;
                if !plaintext.is_empty() || at + len != packet.len() {
                    return None;
                }
                return Some(ClientRequest {
                    transmit,
                    unique_id: unique_id?,
                    cookie: cookie?,
                    placeholders,
                    placeholder_len,
                });
            }
            _ => return None,
        }
        at += len;
    }
    None
}

/// A server response, field by field. `Default` is a good response from a
/// stratum 2 server with one 100-octet cookie.
#[derive(Clone, Debug)]
pub struct ServerReply {
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: [u8; 4],
    pub reference: u64,
    pub receive: u64,
    pub transmit: u64,
    /// The server's AEAD nonce.
    pub nonce: Vec<u8>,
    /// The octet that fills the nonce and ciphertext padding (0 is correct).
    pub pad_byte: u8,
    /// Additional Padding after the ciphertext, inside the authenticator.
    pub additional_padding: Vec<u8>,
    /// Cookies, sent as encrypted NTS Cookie fields.
    pub cookies: Vec<Vec<u8>>,
    /// If set, the plaintext of the encrypted part instead of the cookies.
    pub raw_plaintext: Option<Vec<u8>>,
    /// Whole fields between the Unique Identifier and the authenticator.
    pub plain_fields: Vec<Vec<u8>>,
    /// Octets after the authenticator (unauthenticated).
    pub after_auth: Vec<u8>,
    /// Send the Unique Identifier field.
    pub with_unique_id: bool,
    /// Send the authenticator field.
    pub with_authenticator: bool,
}

impl Default for ServerReply {
    fn default() -> Self {
        Self {
            leap: 0,
            version: 4,
            mode: 4,
            stratum: 2,
            poll: 6,
            precision: -20,
            root_delay: 0x0000_0a00,
            root_dispersion: 0x0000_0500,
            reference_id: [192, 0, 2, 7],
            reference: 0xec00_0000_1000_0000,
            receive: 0xec00_0010_8000_0000,
            transmit: 0xec00_0010_8000_1000,
            nonce: vec![0x3c; 16],
            pad_byte: 0,
            additional_padding: Vec::new(),
            cookies: vec![vec![0xc1; 100]],
            raw_plaintext: None,
            plain_fields: Vec::new(),
            after_auth: Vec::new(),
            with_unique_id: true,
            with_authenticator: true,
        }
    }
}

/// The 48-octet header (RFC 5905 section 7.3).
pub fn header(r: &ServerReply, origin: [u8; 8]) -> Vec<u8> {
    let mut h = vec![(r.leap << 6) | (r.version << 3) | r.mode, r.stratum, r.poll as u8, r.precision as u8];
    h.extend_from_slice(&r.root_delay.to_be_bytes());
    h.extend_from_slice(&r.root_dispersion.to_be_bytes());
    h.extend_from_slice(&r.reference_id);
    h.extend_from_slice(&r.reference.to_be_bytes());
    h.extend_from_slice(&origin);
    h.extend_from_slice(&r.receive.to_be_bytes());
    h.extend_from_slice(&r.transmit.to_be_bytes());
    h
}

/// A response to `req`, authenticated and encrypted with `key` (the S2C key
/// for a good response).
pub fn server_response(key: &[u8; 32], req: &ClientRequest, r: &ServerReply) -> Vec<u8> {
    let mut p = header(r, req.transmit);
    if r.with_unique_id {
        p.extend(field(0x0104, &req.unique_id));
    }
    for f in &r.plain_fields {
        p.extend_from_slice(f);
    }
    if r.with_authenticator {
        let plaintext = match &r.raw_plaintext {
            Some(raw) => raw.clone(),
            None => r.cookies.iter().flat_map(|c| field(0x0204, c)).collect(),
        };
        let ct = seal(key, &p, &r.nonce, &plaintext);
        let pad = |b: &[u8]| {
            let mut v = b.to_vec();
            v.resize(b.len().div_ceil(4) * 4, r.pad_byte);
            v
        };
        let mut body = u16::try_from(r.nonce.len()).unwrap().to_be_bytes().to_vec();
        body.extend_from_slice(&u16::try_from(ct.len()).unwrap().to_be_bytes());
        body.extend(pad(&r.nonce));
        body.extend(pad(&ct));
        body.extend_from_slice(&r.additional_padding);
        p.extend(field(0x0404, &body));
    }
    p.extend_from_slice(&r.after_auth);
    p
}

/// A Kiss-o'-Death response (RFC 5905 section 7.4): leap 3, stratum 0, the
/// code in the reference ID, our origin, and the Unique Identifier if asked.
pub fn kiss_of_death(req: &ClientRequest, code: &[u8; 4], with_unique_id: bool) -> Vec<u8> {
    let r = ServerReply {
        leap: 3,
        stratum: 0,
        reference_id: *code,
        with_unique_id,
        with_authenticator: false,
        ..ServerReply::default()
    };
    server_response(&S2C, req, &r)
}
