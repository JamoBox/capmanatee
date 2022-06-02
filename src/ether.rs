use std::fmt;

pub const IPV4: u16 = 0x0800;
pub const IPV6: u16 = 0x86dd;

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
