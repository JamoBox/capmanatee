// 5 tuples and number of packets for each
use chrono::NaiveDateTime;
use clap::Parser;
use ctrlc;
use pcap::{Device, Packet};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const TCP: u8 = 6;
const UDP: u8 = 17;

const IPV4: u16 = 0x0800;
const IPV6: u16 = 0x86dd;

#[derive(Eq, PartialEq, Hash)]
struct FiveTuple {
    ether: Ethertype,
    l3_src: u128,
    l3_dst: u128,
    next_proto: u8,
    l4_sport: u16,
    l4_dport: u16,
}

impl FiveTuple {
    fn new() -> Self {
        Self {
            ether: Ethertype::UNKNOWN,
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
        let mut l3_src = String::new();
        let mut l3_dst = String::new();

        fn v6_convert(addr: u128, formatted: &mut String) {
            let bytes = addr.to_be_bytes();
            formatted.push_str(&format!("{:02x}{:02x}", bytes[0], bytes[1]));
            for i in (2..16).step_by(2) {
                formatted.push_str(&format!(
                    ":{:02x}{:02x}",
                    bytes[i],
                    bytes[i + 1]
                ));
            }
        }

        fn v4_convert(addr: u128, formatted: &mut String) {
            let bytes = (addr as u32).to_be_bytes();
            formatted.push_str(&format!("{}", bytes[0]));
            for i in 1..4 {
                formatted.push_str(&format!(".{}", bytes[i]));
            }
        }

        if self.ether == Ethertype::IPV6 {
            v6_convert(self.l3_src, &mut l3_src);
            v6_convert(self.l3_dst, &mut l3_dst);
        }
        if self.ether == Ethertype::IPV4 {
            v4_convert(self.l3_src, &mut l3_src);
            v4_convert(self.l3_dst, &mut l3_dst);
        }

        write!(
            f,
            "{}:{} -> {}:{} ({})",
            l3_src, self.l4_sport, l3_dst, self.l4_dport, self.next_proto
        )
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Ethertype {
    IPV4 = IPV4,
    IPV6 = IPV6,
    UNKNOWN,
}

impl fmt::Display for Ethertype {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "{:?} (0x{:04X})", self, *self as u16);
    }
}

pub fn to_ethertype(value: u16) -> Ethertype {
    return match value {
        IPV4 => Ethertype::IPV4,
        IPV6 => Ethertype::IPV6,
        _ => Ethertype::UNKNOWN,
    };
}

fn handle_ipv4(
    pkt: &Packet,
    offset: usize,
    fivetuple: &mut FiveTuple,
) -> usize {
    fn getaddr(pkt: &Packet, ip_offset: usize, pos: usize) -> u32 {
        let mut addr = 0;
        for i in 0..4 {
            addr = addr | {
                (pkt.data[ip_offset + (pos + i)] as u32) << 24 - (8 * i)
            };
        }
        return addr;
    }

    let ihl: u8 = (pkt.data[offset] & 0xf) * 4;

    let next_offset: usize = offset + ihl as usize;

    fivetuple.next_proto = pkt.data[offset + 9];
    fivetuple.l3_src = getaddr(&pkt, offset, 12) as u128;
    fivetuple.l3_dst = getaddr(&pkt, offset, 16) as u128;

    return next_offset;
}

fn handle_ipv6(
    pkt: &Packet,
    offset: usize,
    fivetuple: &mut FiveTuple,
) -> usize {
    fn getaddr(pkt: &Packet, ip_offset: usize, pos: usize) -> u128 {
        let mut addr = 0;
        for i in 0..16 {
            addr = addr | {
                (pkt.data[ip_offset + (pos + i)] as u128) << 120 - (8 * i)
            };
        }
        return addr;
    }

    fivetuple.next_proto = pkt.data[offset + 6];
    fivetuple.l3_src = getaddr(&pkt, offset, 8) as u128;
    fivetuple.l3_dst = getaddr(&pkt, offset, 24) as u128;

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

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    let verbose: bool = args.verbose;

    let mut dev = Device::lookup().unwrap().open().unwrap();
    let mut pktmap = HashMap::<FiveTuple, u128>::new();

    let running = Arc::new(AtomicBool::new(true));
    let _running = running.clone();

    ctrlc::set_handler(move || {
        _running.store(false, Ordering::SeqCst);
    })
    .unwrap();

    while let Ok(pkt) = dev.next() {
        let ts = NaiveDateTime::from_timestamp(
            pkt.header.ts.tv_sec,
            pkt.header.ts.tv_usec as u32,
        );

        let mut fivetuple = FiveTuple::new();

        fivetuple.ether = get_ethertype(&pkt);
        let eth_callback = match fivetuple.ether {
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

        if verbose {
            print!("[{}] {} -- ", ts, fivetuple);
        }

        let count = pktmap.entry(fivetuple).or_insert(0);
        *count += 1;

        if verbose {
            println!("{}", count);
        }

        if !running.load(Ordering::SeqCst) {
            break;
        }
    }

    let mut scored: Vec<_> = pktmap.iter().collect();
    scored.sort_by(|a, b| a.1.cmp(b.1));

    println!("");
    println!(" -- STATS -- ");
    for entry in scored.iter() {
        println!("{}: {}", entry.0, entry.1);
    }
}
