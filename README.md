# xdp-nat

## Why this exists?

When developing a stateless maglev load balancer using ipvs, we realized that return traffic was not being snatted on directors without proper conntrack entries created when the traffic was first forwarded using ipvs, it was realized that return traffic snat depends on conntrack entries. Since only a single director receives inbound traffic, returning packets transiting another director were being silently dropped. Since exact snat rules are known in advance and stateless, we run this small xdp program on the anycast vtep interface of directors instead of relying on conntrack.

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --iface eth0
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package xdp-nat --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/xdp-nat` can be
copied to a Linux server or VM and run there.

## Adding nat entries

The only quirk is that IPs need to be split in bytes. Decimal and hexadecimal
notations are supported.

i.e:

192.168.0.254:TCP:443 -> 1.2.3.4:TCP:23
```
bpftool map update name SNAT_TABLE key 192 168 0 254 0xbb 0x1 6 0 value 1 2 3 4 0 23 0 0
```

Notes on the format:

1. Key and value formats : ip (4 bytes), port (2 bytes), protocol (single byte padded with 0x0)
2. The byte order for the key's port is reversed from the value
3. The protocol field of the value is ignored
