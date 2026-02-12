use traffic_analyzer_common::IpKey;

const DNS_HEADER_LEN: usize = 12;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;

#[derive(Debug, Clone)]
pub struct ParsedDns {
    pub query: Option<(String, u16)>,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub domain: String,
    pub ip: IpKey,
    pub ttl_sec: u32,
}

pub fn parse_dns_payload(payload: &[u8], src_port: u16, dst_port: u16) -> Option<ParsedDns> {
    if payload.len() < DNS_HEADER_LEN {
        return None;
    }

    let flags = be_u16(payload, 2)?;
    let qr = (flags & 0x8000) != 0;
    let qdcount = usize::from(be_u16(payload, 4)?);
    let ancount = usize::from(be_u16(payload, 6)?);
    if qdcount == 0 {
        return None;
    }

    let (qname, name_consumed) = parse_dns_name(payload, DNS_HEADER_LEN)?;
    let mut off = DNS_HEADER_LEN + name_consumed;
    if off + 4 > payload.len() {
        return None;
    }

    let qtype = be_u16(payload, off)?;
    off += 2;
    let _qclass = be_u16(payload, off)?;
    off += 2;

    let mut out = ParsedDns {
        query: None,
        answers: Vec::new(),
    };

    if !qr && dst_port == 53 {
        out.query = Some((qname.clone(), qtype));
        return Some(out);
    }

    if !qr || src_port != 53 || ancount == 0 {
        return None;
    }

    let max_answers = core::cmp::min(ancount, 4);
    for _ in 0..max_answers {
        let (_, consumed) = match parse_dns_name(payload, off) {
            Some(v) => v,
            None => break,
        };
        off += consumed;
        if off + 10 > payload.len() {
            break;
        }

        let typ = match be_u16(payload, off) {
            Some(v) => v,
            None => break,
        };
        let class = match be_u16(payload, off + 2) {
            Some(v) => v,
            None => break,
        };
        let ttl = match be_u32(payload, off + 4) {
            Some(v) => v,
            None => break,
        };
        let rdlen = match be_u16(payload, off + 8) {
            Some(v) => usize::from(v),
            None => break,
        };

        let rdata_off = off + 10;
        if rdata_off + rdlen > payload.len() {
            break;
        }

        if class == 1 && typ == DNS_TYPE_A && rdlen == 4 {
            let mut ip = [0u8; 16];
            ip[10] = 0xff;
            ip[11] = 0xff;
            ip[12..16].copy_from_slice(&payload[rdata_off..rdata_off + 4]);
            out.answers.push(DnsAnswer {
                domain: qname.clone(),
                ip: IpKey { ip },
                ttl_sec: ttl,
            });
        } else if class == 1 && typ == DNS_TYPE_AAAA && rdlen == 16 {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&payload[rdata_off..rdata_off + 16]);
            out.answers.push(DnsAnswer {
                domain: qname.clone(),
                ip: IpKey { ip },
                ttl_sec: ttl,
            });
        }

        off = rdata_off + rdlen;
    }

    Some(out)
}

fn parse_dns_name(payload: &[u8], start_off: usize) -> Option<(String, usize)> {
    let mut off = start_off;
    let mut consumed = 0usize;
    let mut jumped = false;
    let mut jumps = 0usize;
    let mut name = String::new();

    loop {
        if off >= payload.len() {
            return None;
        }

        let len = payload[off];
        if (len & 0xc0) == 0xc0 {
            if off + 1 >= payload.len() {
                return None;
            }
            let ptr = (((len as usize) & 0x3f) << 8) | (payload[off + 1] as usize);
            if !jumped {
                consumed += 2;
                jumped = true;
            }
            off = ptr;
            jumps += 1;
            if jumps > 8 {
                return None;
            }
            continue;
        }

        if len == 0 {
            if !jumped {
                consumed += 1;
            }
            break;
        }

        if (len & 0xc0) != 0 {
            return None;
        }

        let label_len = usize::from(len);
        off += 1;
        if off + label_len > payload.len() {
            return None;
        }

        if !name.is_empty() {
            name.push('.');
        }
        let label = &payload[off..off + label_len];
        name.push_str(&String::from_utf8_lossy(label).to_lowercase());

        if !jumped {
            consumed += 1 + label_len;
        }
        off += label_len;
    }

    Some((name, consumed))
}

fn be_u16(payload: &[u8], off: usize) -> Option<u16> {
    if off + 2 > payload.len() {
        return None;
    }
    Some(((payload[off] as u16) << 8) | payload[off + 1] as u16)
}

fn be_u32(payload: &[u8], off: usize) -> Option<u32> {
    if off + 4 > payload.len() {
        return None;
    }
    Some(
        ((payload[off] as u32) << 24)
            | ((payload[off + 1] as u32) << 16)
            | ((payload[off + 2] as u32) << 8)
            | (payload[off + 3] as u32),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_query_ok() {
        // standard query for example.com A.
        let payload: [u8; 29] = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        let parsed = parse_dns_payload(&payload, 5353, 53).unwrap();
        assert_eq!(parsed.query, Some(("example.com".to_string(), 1)));
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn parse_dns_response_a_ok() {
        // response for example.com A 1.2.3.4 with compressed answer name.
        let payload: [u8; 45] = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x01,
            0x02, 0x03, 0x04,
        ];

        let parsed = parse_dns_payload(&payload, 53, 5353).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].domain, "example.com");
        assert_eq!(parsed.answers[0].ttl_sec, 60);
        assert_eq!(parsed.answers[0].ip.ip[12..16], [1, 2, 3, 4]);
    }
}
