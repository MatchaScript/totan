# Known Issues / Follow-ups

Tracked problems that are understood but not yet fixed.

## eBPF host-hook cgroup attach fails with EINVAL in CI

**Status:** open · pre-existing · surfaced by PR #9 (`3e3b134`, 2026-06-13)

### Symptom

The `E2E (eBPF, PAC routing)` CI job fails at totan startup:

```
ERROR totan: Interceptor error: attaching connect4 to /sys/fs/cgroup/totan-e2e.slice
Error: attaching connect4 to /sys/fs/cgroup/totan-e2e.slice
  0: `bpf_link_create` failed
  1: Invalid argument (os error 22)
```

Because `run_ebpf` bails when the host-hook attach fails, totan exits immediately
and **every** eBPF e2e scenario times out (`mode: ebpf  passed: 3  failed: 28`),
not just the host-cgroup ones (H1/H2).

### Root cause

`aya` 0.13.1's `CgroupSockAddr::attach` takes the kernel ≥ 5.7 link path and
passes `CgroupAttachMode::AllowMultiple` → `BPF_F_ALLOW_MULTI` as the `flags`
argument to `bpf_link_create`. The CI kernel rejects that flag on the cgroup
link-create path with `EINVAL`. All three host-hook attach helpers in
[`totan/src/cgroup.rs`](../totan/src/cgroup.rs) (`attach_connect4`,
`attach_sockops`, `attach_sock_release`) use `AllowMultiple` deliberately, for
Cilium coexistence.

### Why it's pre-existing (not the robustness work)

- `origin/main` was 7 weeks behind (`adbff62c`) and had **no** `cgroup.rs` — the
  host-hook feature commits (2026-05-06) only ever lived on the feature branch,
  so the cgroup `connect4` H1/H2 scenarios had **never run through CI** before
  PR #9 exercised them.
- Reverting the PR's connect4 change reproduced the **identical** EINVAL (program
  back to its base size), confirming the attach failure is in the base host-hook
  code, not in the added self-loop guard.

### Impact

- The host-hook datapath cannot be end-to-end verified in CI.
- Consequently the cgroup `connect4` **self-loop guard** added in PR #9
  (`totan_self_in_slice` in `cgroup.rs`) is only unit-tested, not e2e-verified —
  it refuses to start totan inside a hooked slice; the guard logic itself is
  covered by `cgroup_within_detects_membership` / `slice_path_maps_to_cgroup_rel`.

### Things to try

1. `CgroupAttachMode::Single` instead of `AllowMultiple` (changes attach
   semantics — weigh against the Cilium-coexistence intent).
2. Gate or fall back the link-vs-`prog_attach` attach path by kernel/runner.
3. If GitHub Actions runners genuinely can't do cgroup BPF link attach to a
   transient slice, skip H1/H2 in the GH `ebpf` e2e and cover them on a real
   host instead.

It likely works on a real host (the feature was developed and presumably tested
locally), so **confirm whether the failure is environment-specific before
changing the intentional `AllowMultiple` design.**
