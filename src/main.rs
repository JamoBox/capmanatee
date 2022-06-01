// 5 tuples and number of packets for each
mod ether;

use chrono::NaiveDateTime;
use pcap::{Device, Packet};
use std::fmt;

use ether::{to_ethertype, Ethertype};

const TCP: u8 = 6;
const UDP: u8 = 17;

struct FiveTuple {
    l3_src: u64,
    l3_dst: u64,
    next_proto: u8,
    l4_sport: u16,
    l4_dport: u16,
}

impl FiveTuple {
    fn new() -> Self {
        Self {
            l3_src: 0,
            l3_dst: 0,
            next_proto: 0,
            l4_sport: 0,
            l4_dport: 0,
        }
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.l3_src,
            self.l4_sport,
            self.l3_dst,
            self.l4_dport,
            self.next_proto
        )
    }
}

fn handle_ipv4(
    pkt: &Packet,
    offset: usize,
    fivetuple: &mut FiveTuple,
) -> usize {
    fn getaddr(pkt: &Packet, ip_offset: usize, pos: usize) -> u32 {
        let mut addr = 0;
        for i in 0..3 {
            addr = addr | {
                (pkt.data[ip_offset + (pos + i)] as u32) << 24 - (8 * i)
            };
        }
        return addr;
    }

    let ihl: u8 = (pkt.data[offset] & 0xf) * 4;

    let next_offset: usize = offset + ihl as usize;

    fivetuple.next_proto = pkt.data[offset + 9];
    fivetuple.l3_src = getaddr(&pkt, offset, 12) as u64;
    fivetuple.l3_dst = getaddr(&pkt, offset, 16) as u64;

    return next_offset;
}

fn handle_ipv6(
    pkt: &Packet,
    offset: usize,
    fivetuple: &mut FiveTuple,
) -> usize {
    fn getaddr(pkt: &Packet, ip_offset: usize, pos: usize) -> u64 {
        let mut addr = 0;
        for i in 0..7 {
            addr = addr | {
                (pkt.data[ip_offset + (pos + i)] as u64) << 56 - (8 * i)
            };
        }
        return addr;
    }

    fivetuple.next_proto = pkt.data[offset + 6];
    fivetuple.l3_src = getaddr(&pkt, offset, 8) as u64;
    fivetuple.l3_dst = getaddr(&pkt, offset, 24) as u64;

    return offset + 40;
}

fn handle_unknown(
    _pkt: &Packet,
    _offset: usize,
    _fivetuple: &mut FiveTuple,
) -> usize {
    // println!("Ethertype not implemented");
    return 0;
}

fn get_ethertype(pkt: &Packet) -> Ethertype {
    let value: u16 = ((pkt.data[12] as u16) << 8) | (pkt.data[13] as u16);
    return to_ethertype(value);
}

fn main() {
    let mut dev = Device::lookup().unwrap().open().unwrap();

    while let Ok(pkt) = dev.next() {
        let ts = NaiveDateTime::from_timestamp(
            pkt.header.ts.tv_sec,
            pkt.header.ts.tv_usec as u32,
        );
        let mut fivetuple = FiveTuple::new();

        let eth_callback = match get_ethertype(&pkt) {
            Ethertype::IPV4 => handle_ipv4,
            Ethertype::IPV6 => handle_ipv6,
            _ => handle_unknown,
        };
        let next_offset = eth_callback(&pkt, 14, &mut fivetuple);

        match fivetuple.next_proto {
            TCP | UDP => {
                fivetuple.l4_sport = ((pkt.data[next_offset] as u16) << 8)
                    | pkt.data[next_offset + 1] as u16;
                fivetuple.l4_dport = ((pkt.data[next_offset + 2] as u16) << 8)
                    | pkt.data[next_offset + 3] as u16;
            }
            _ => {}
        }

        println!("[{}] {} -- {}", ts, fivetuple, next_offset);
    }
}
