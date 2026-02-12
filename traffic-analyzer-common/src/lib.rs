#![cfg_attr(not(feature = "user"), no_std)]

use bytemuck::{Pod, Zeroable};

pub const MAX_DOMAIN_LEN: usize = 128;
pub const DNS_EVENT_PAYLOAD_LEN: usize = 96;
pub const TLS_EVENT_PAYLOAD_LEN: usize = 384;
pub const FLOW_STATS_MAX_ENTRIES: u32 = 131_072;
pub const COLLECTOR_STATS_MAP_ENTRIES: u32 = 8;
pub const COLLECTOR_STAT_FLOW_INSERT_DROP_IDX: u32 = 0;
pub const COLLECTOR_STAT_DNS_RINGBUF_DROP_IDX: u32 = 1;
pub const COLLECTOR_STAT_TLS_RINGBUF_DROP_IDX: u32 = 2;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Direction {
    #[default]
    Ingress = 0,
    Egress = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Pod, Zeroable)]
pub struct FlowKey {
    pub direction: u8,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Pod, Zeroable)]
pub struct FlowValue {
    pub bytes: u64,
    pub packets: u64,
    pub last_seen_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Pod, Zeroable)]
pub struct DnsQueryKey {
    pub qname_len: u16,
    pub qtype: u16,
    pub qname: [u8; MAX_DOMAIN_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Pod, Zeroable)]
pub struct DnsEvent {
    pub ts_ns: u64,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_len: u16,
    pub captured_len: u16,
    pub direction: u8,
    pub _pad: [u8; 7],
    pub payload: [u8; DNS_EVENT_PAYLOAD_LEN],
}

impl Default for DnsEvent {
    fn default() -> Self {
        Self {
            ts_ns: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            payload_len: 0,
            captured_len: 0,
            direction: 0,
            _pad: [0; 7],
            payload: [0; DNS_EVENT_PAYLOAD_LEN],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsEvent {
    pub ts_ns: u64,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_len: u16,
    pub captured_len: u16,
    pub direction: u8,
    pub _pad: [u8; 7],
    pub payload: [u8; TLS_EVENT_PAYLOAD_LEN],
}

impl Default for TlsEvent {
    fn default() -> Self {
        Self {
            ts_ns: 0,
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 0,
            dst_port: 0,
            payload_len: 0,
            captured_len: 0,
            direction: 0,
            _pad: [0; 7],
            payload: [0; TLS_EVENT_PAYLOAD_LEN],
        }
    }
}

unsafe impl Zeroable for TlsEvent {}
unsafe impl Pod for TlsEvent {}

impl Default for DnsQueryKey {
    fn default() -> Self {
        Self {
            qname_len: 0,
            qtype: 0,
            qname: [0; MAX_DOMAIN_LEN],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Pod, Zeroable)]
pub struct IpKey {
    pub ip: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Pod, Zeroable)]
pub struct DomainValue {
    pub expires_at_ns: u64,
    pub domain_len: u16,
    pub _pad: u16,
    pub domain: [u8; MAX_DOMAIN_LEN],
    pub _trailing_pad: [u8; 4],
}

impl Default for DomainValue {
    fn default() -> Self {
        Self {
            expires_at_ns: 0,
            domain_len: 0,
            _pad: 0,
            domain: [0; MAX_DOMAIN_LEN],
            _trailing_pad: [0; 4],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsQueryKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DomainValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TlsEvent {}
