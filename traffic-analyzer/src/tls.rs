const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;
const TLS_EXT_SERVER_NAME: u16 = 0;

pub fn parse_tls_client_hello_sni(payload: &[u8], _src_port: u16, dst_port: u16) -> Option<String> {
    if dst_port != 443 {
        return None;
    }
    if payload.len() < 5 {
        return None;
    }
    if payload[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return None;
    }

    let record_len = usize::from(be_u16(payload, 3)?);
    if record_len < 4 {
        return None;
    }
    let record_end = (5 + record_len).min(payload.len());

    let mut off = 5usize;
    if payload.get(off).copied()? != TLS_HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    off += 1;

    let hs_len = be_u24(payload, off)?;
    off += 3;
    if hs_len < 34 {
        return None;
    }
    let hs_end = (off + hs_len).min(record_end);

    // client_version + random
    off += 2 + 32;
    if off >= hs_end {
        return None;
    }

    // session id
    let sid_len = usize::from(*payload.get(off)?);
    off += 1 + sid_len;
    if off + 2 > hs_end {
        return None;
    }

    // cipher suites
    let cipher_len = usize::from(be_u16(payload, off)?);
    off += 2 + cipher_len;
    if off >= hs_end {
        return None;
    }

    // compression methods
    let comp_len = usize::from(*payload.get(off)?);
    off += 1 + comp_len;
    if off + 2 > hs_end {
        return None;
    }

    // extensions
    let ext_len = usize::from(be_u16(payload, off)?);
    off += 2;
    let ext_end = (off + ext_len).min(hs_end);

    while off + 4 <= ext_end {
        let ext_type = be_u16(payload, off)?;
        let ext_data_len = usize::from(be_u16(payload, off + 2)?);
        off += 4;
        if off + ext_data_len > ext_end {
            break;
        }

        if ext_type == TLS_EXT_SERVER_NAME {
            return parse_sni_ext(&payload[off..off + ext_data_len]);
        }
        off += ext_data_len;
    }

    None
}

fn parse_sni_ext(ext: &[u8]) -> Option<String> {
    if ext.len() < 5 {
        return None;
    }
    let list_len = usize::from(be_u16(ext, 0)?);
    if list_len + 2 > ext.len() {
        return None;
    }

    let mut off = 2usize;
    while off + 3 <= ext.len() {
        let name_type = ext[off];
        let name_len = usize::from(be_u16(ext, off + 1)?);
        off += 3;
        if off + name_len > ext.len() {
            return None;
        }
        if name_type == 0 {
            let raw = &ext[off..off + name_len];
            let s = String::from_utf8_lossy(raw).to_lowercase();
            if !s.is_empty() {
                return Some(s);
            }
        }
        off += name_len;
    }

    None
}

fn be_u16(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 > data.len() {
        return None;
    }
    Some(((data[off] as u16) << 8) | (data[off + 1] as u16))
}

fn be_u24(data: &[u8], off: usize) -> Option<usize> {
    if off + 3 > data.len() {
        return None;
    }
    Some(((data[off] as usize) << 16) | ((data[off + 1] as usize) << 8) | data[off + 2] as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sni_ok() {
        // minimal-ish TLS ClientHello carrying SNI "example.com"
        let payload: [u8; 72] = [
            0x16, 0x03, 0x01, 0x00, 0x43, // record
            0x01, 0x00, 0x00, 0x3f, // handshake header
            0x03, 0x03, // client_version
            // random (32)
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 0x00, // session id len
            0x00, 0x02, 0x13, 0x01, // cipher suites
            0x01, 0x00, // compression
            0x00, 0x14, // extensions len
            0x00, 0x00, 0x00, 0x10, // ext: server_name, len=16
            0x00, 0x0e, // server_name_list len=14
            0x00, 0x00, 0x0b, // host_name, len=11
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        ];

        let sni = parse_tls_client_hello_sni(&payload, 52341, 443).unwrap();
        assert_eq!(sni, "example.com");
    }
}
