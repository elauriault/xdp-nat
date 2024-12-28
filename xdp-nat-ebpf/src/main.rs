#![no_std]
#![no_main]
#![allow(unused_imports)]
#![allow(dead_code)]

use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};

use xdp_nat_common::PacketLog;

// const ETH_HDR_LEN: usize = mem::size_of::<EthHdr>();
// const IP_HDR_LEN: usize = mem::size_of::<Ipv4Hdr>();

#[xdp]
pub fn xdp_nat(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_nat(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
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
    let ip: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    // let mut pkt: TCPIPxdp = TCPIPxdp::default();
    let saddr = u32::from_be(unsafe { (*ip).src_addr });
    let daddr = u32::from_be(unsafe { (*ip).dst_addr });
    let mut sport = 0;
    // let mut dport = 0;
    match unsafe { (*ip).proto } {
        IpProto::Tcp => {
            let hdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            sport = u16::from_be(unsafe { *hdr }.source);
            // dport = u16::from_be(unsafe { *hdr }.dest);
        }
        IpProto::Udp => {
            let hdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            sport = u16::from_be(unsafe { *hdr }.source);
            // dport = u16::from_be(unsafe { *hdr }.dest);
        }
        _ => {}
    };
    let protocol = unsafe { (*ip).proto } as u32;

    let key = ((saddr as u64) + ((daddr as u64) << 32) as u64) as u64;

    if let Some(value) = SNAT_TABLE.get(&key) {
        info!(
            &ctx,
            "received an ip packet: {}:{} {}", saddr, sport, protocol
        );

        let snat = (*value) as u32;
        let port = (*value >> 32) as u16;
        let mip: *mut Ipv4Hdr = ip as *mut Ipv4Hdr;
        let oldsaddr = (*mip).src_addr;
        let oldcheck = (*mip).check;
        (*mip).src_addr = snat;
        (*mip).check = l3csumdiff(oldsaddr, snat, oldcheck);

        match unsafe { (*ip).proto } {
            IpProto::Tcp => {
                let hdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + ((*ip).ihl() * 4) as usize)?;
                let mhdr: *mut TcpHdr = hdr as *mut TcpHdr;
                let oldport = (*mhdr).source;
                let oldcheck = (*mhdr).check;
                (*mhdr).source = port;
                (*mhdr).check = l4csumdiff(oldsaddr, snat, oldport, port, oldcheck);
            }
            IpProto::Udp => {
                let hdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + ((*ip).ihl() * 4) as usize)?;
                let mhdr: *mut UdpHdr = hdr as *mut UdpHdr;
                let oldport = (*mhdr).source;
                let oldcheck = (*mhdr).check;
                (*mhdr).source = port;
                if oldcheck != 0 {
                    (*mhdr).check = l4csumdiff(oldsaddr, snat, oldport, port, oldcheck);
                }
            }
            _ => {}
        };
    }

    Ok(xdp_action::XDP_PASS)
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
