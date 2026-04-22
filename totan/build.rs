//! Build-time driver for the eBPF kernel-space crate.
//!
//! Only active under the `ebpf` cargo feature — the netfilter-only default
//! build requires neither bpf-linker nor a nightly toolchain.

#[cfg(feature = "ebpf")]
fn main() {
    use aya_build::{Package, Toolchain};

    // Pin the same nightly channel as totan-ebpf/rust-toolchain.toml so
    // rustup run selects a consistent toolchain regardless of the ambient
    // `+channel` on the caller's shell.
    aya_build::build_ebpf(
        [Package {
            name: "totan-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../totan-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Custom("nightly-2026-03-01"),
    )
    .expect("failed to build totan-ebpf");
}

#[cfg(not(feature = "ebpf"))]
fn main() {}
