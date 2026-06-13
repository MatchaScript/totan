# Known Issues / Follow-ups

Tracked problems and their resolutions.

## eBPF host-hook datapath never loaded in CI — RESOLVED

**Status:** resolved · verified locally on Linux 6.19 and in CI on Linux 6.17 ·
surfaced by PR #9 (`3e3b134`, 2026-06-13), fixed in PR #10

The cgroup host-hook subsystem (`cgroup/connect4` + `sockops`, plus a since-
removed `sock_release`) had **never run end-to-end** before PR #9 wired the H1/H2
scenarios into CI: `origin/main` was 7 weeks behind (`adbff62c`) with no
`cgroup.rs`, and the dev host masked both bugs below. Two independent defects had
to be fixed before the host-hook datapath loaded.

### Layer 1 — attach failed with `EINVAL`

totan exited at startup; **every** eBPF e2e scenario timed out
(`mode: ebpf  passed: 3  failed: 28`), not just the host-cgroup ones:

```
attaching connect4 to /sys/fs/cgroup/totan-e2e.slice
  0: `bpf_link_create` failed
  1: Invalid argument (os error 22)
```

**Cause.** The attach helpers passed `CgroupAttachMode::AllowMultiple`, which aya
translates to `BPF_F_ALLOW_MULTI` in the `bpf_link_create` flags field. On the
bpf_link path (kernel ≥ 5.7, which `check_prereqs` already requires) the kernel
requires that field to be **zero** for cgroup links and applies multi semantics
internally, so a non-zero value is rejected with `EINVAL` on kernels predating
cgroup-link flag support.

**Fix.** Use `CgroupAttachMode::Single` (`flags == 0`). Link attachments still
coexist with Cilium's cgroup programs (the kernel treats links as multi
internally). Precedent: Cilium attaches its own `connect4` link with `flags == 0`
(`link.AttachRawLink`, no `Flags` set, in `reference/cilium/pkg/socketlb/cgroup.go`);
aya's `CgroupSockAddr` doc example uses `Single`.

### Layer 2 — `sock_release` could not load (verifier)

With Layer 1 fixed, `connect4`/`sockops` attached but the next program failed the
verifier:

```
; #[cgroup_sock(sock_release)] @ main.rs:328
0: (61) r1 = *(u32 *)(r1 +44)
invalid bpf_context access off=44 size=4
```

**Cause.** `totan_sock_release` read `bpf_sock.src_port` (offset 44) to evict the
sport-keyed map entry. A `cgroup/sock_release` program **cannot read `src_port` at
any width** — narrowing the load to 16 bits still failed
(`invalid bpf_context access off=44 size=2`). This reproduced identically on the
dev host (6.19) and CI (6.17), so the hook had never loaded on **any** kernel; the
Layer 1 `EINVAL` had always aborted startup before it was reached. (Cilium reads
`src_port` only from `post_bind` programs, via the narrow `ctx_src_port`; its own
`sock_release` keys cleanup by socket cookie + `dst_ip4`/`dst_port`, never
`src_port`.)

**Fix.** Removed the `sock_release` hook entirely. It was a non-essential safety
net: the accept loop evicts each sport entry right after reading it (primary
cleanup), `sockops` overwrites on sport reuse (so a stale entry can never be
mis-served), and `TOTAN_OD_BY_SPORT` is an LRU map that bounds growth on its own.
Entries for connections that are never accepted now age out of the LRU instead of
being freed at socket close — no correctness impact.

### Verification

`toolkit/e2e/run.sh ebpf` passes end-to-end (`passed: 31  failed: 0`), including
the host-cgroup scenarios H1 (host HTTP), H2 (host HTTPS) and H3 (out-of-slice
traffic not intercepted), on both Linux 6.19 (dev host) and the Linux 6.17 CI
runner. The `connect4` self-loop guard added in PR #9 (`totan_self_in_slice`) is
now exercised by a live datapath rather than unit tests alone.
