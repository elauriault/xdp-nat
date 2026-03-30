#![no_std]
#![no_main]
#![allow(unused_imports)]
#![allow(dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};

use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[xdp]
pub fn xdp_nat(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_nat(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[map(name = "SNAT_TABLE")]
static SNAT_TABLE: HashMap<u64, u64> = HashMap::with_max_entries(10240, 0);

unsafe fn try_xdp_nat(ctx: XdpContext) -> Result<u32, ()> {
    unsafe {
        let ip: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
        let l4_offset = EthHdr::LEN + (*ip).ihl() as usize;
        let saddr = u32::from_be_bytes((*ip).src_addr);
        let mut sport = 0;
        match (*ip).proto {
            IpProto::Tcp => {
                let hdr: *const TcpHdr = ptr_at(&ctx, l4_offset)?;
                sport = u16::from_be_bytes((*hdr).source);
            }
            IpProto::Udp => {
                let hdr: *const UdpHdr = ptr_at(&ctx, l4_offset)?;
                sport = u16::from_be_bytes((*hdr).src);
            }
            _ => {}
        };
        let protocol = (*ip).proto as u32;

        let key =
            (saddr.to_be() as u64) | ((sport.to_be() as u64) << 32) | ((protocol as u64) << 48);

        if let Some(value) = SNAT_TABLE.get(&key) {
            info!(
                &ctx,
                "received an ip packet: {}.{}.{}.{}:{} {}",
                (saddr >> 24) as u8,
                (saddr >> 16) as u8,
                (saddr >> 8) as u8,
                saddr as u8,
                sport,
                protocol
            );

            let snat = (*value) as u32;
            let port = (*value >> 32) as u16;
            let mip: *mut Ipv4Hdr = ip as *mut Ipv4Hdr;
            let oldsaddr = u32::from_ne_bytes((*mip).src_addr);
            let oldcheck = u16::from_ne_bytes((*mip).check);
            (*mip).src_addr = snat.to_ne_bytes();
            (*mip).check = l3csumdiff(oldsaddr, snat, oldcheck).to_ne_bytes();

            match (*ip).proto {
                IpProto::Tcp => {
                    let hdr: *const TcpHdr = ptr_at(&ctx, l4_offset)?;
                    let mhdr: *mut TcpHdr = hdr as *mut TcpHdr;
                    let oldport = u16::from_ne_bytes((*mhdr).source);
                    let oldcheck = u16::from_ne_bytes((*mhdr).check);
                    (*mhdr).source = port.to_ne_bytes();
                    (*mhdr).check =
                        l4csumdiff(oldsaddr, snat, oldport, port, oldcheck).to_ne_bytes();
                }
                IpProto::Udp => {
                    let hdr: *const UdpHdr = ptr_at(&ctx, l4_offset)?;
                    let mhdr: *mut UdpHdr = hdr as *mut UdpHdr;
                    let oldport = u16::from_ne_bytes((*mhdr).src);
                    let oldcheck = u16::from_ne_bytes((*mhdr).check);
                    (*mhdr).src = port.to_ne_bytes();
                    if oldcheck != 0 {
                        (*mhdr).check =
                            l4csumdiff(oldsaddr, snat, oldport, port, oldcheck).to_ne_bytes();
                    }
                }
                _ => {}
            };
        }

        Ok(xdp_action::XDP_PASS)
    }
}

#[inline]
pub fn splitu32(input: u32) -> [u16; 2] {
    let r1 = (input & 0xffff) as u16;
    let r2 = input >> 16;
    let r2 = (r2 & 0xffff) as u16;
    [r1, r2]
}

#[inline]
pub fn l3csumdiff(oldip: u32, newip: u32, oldcsum: u16) -> u16 {
    let mut csum: u64 = !oldcsum as u64;
    let old = splitu32(oldip);
    let new = splitu32(newip);
    (0..2).for_each(|i| {
        csum -= old[i] as u64;
    });
    csum = (csum & 0xffff) + (csum >> 16);
    (0..2).for_each(|i| {
        csum += new[i] as u64;
    });
    csum = (csum & 0xffff) + (csum >> 16);
    !(csum as u16)
}

#[inline]
pub fn l4csumdiff(oldip: u32, newip: u32, oldport: u16, newport: u16, oldcsum: u16) -> u16 {
    let mut csum: u64 = !oldcsum as u64;
    let old = splitu32(oldip);
    let new = splitu32(newip);
    (0..2).for_each(|i| {
        csum -= old[i] as u64;
    });
    csum -= oldport as u64;
    csum = (csum & 0xffff) + (csum >> 16);
    (0..2).for_each(|i| {
        csum += new[i] as u64;
    });
    csum += newport as u64;
    csum = (csum & 0xffff) + (csum >> 16);
    !(csum as u16)
}
