# totan - Transparent Proxy Application

## Project Overview
`totan` is an eBPF-only transparent proxy application that relays intercepted connections to an upstream proxy server.

## Core Specifications & Features
- **Traffic Interception**: 
  - Uses tc ingress programs for client/container traffic and cgroup hooks for host-originated traffic.
- **Proxy Relay Mechanism**:
  - **HTTP Traffic**: Relayed to the upstream proxy as standard HTTP proxy requests.
  - **HTTPS Traffic**: Uses the `HTTP CONNECT` method against the upstream proxy to establish a TCP tunnel before relaying the TLS traffic.

## Project Structure
- `totan/`: The main userspace proxy application (Rust).
- `totan-ebpf/`: Kernel-space eBPF programs for traffic interception.
- `totan-common/`: Shared Rust crate for structs/constants used by both userspace and kernel-space.
- `toolkit/`: Utilities and e2e test scripts (`e2e/run.sh`, `e2e/stress.sh`).

## Instructions for AI Agents
When generating, modifying, or reviewing code, strictly adhere to the following:

1. **Technology Stack**:
   - Primary language: **Rust**.
   - Remember nuances of eBPF and Rust integration (e.g., the Aya framework).

2. **Transparent Proxy Constraints**:
   - Always ensure the correct retrieval of the Original Destination IP/Port via the assigned socket or eBPF maps.
   - Accurately implement relay logic differences: plain-text forwarding for HTTP and TCP tunneling via `HTTP CONNECT` for HTTPS.

3. **Testing & Validation**:
   - Because network behavior is complex, strongly prioritize running and updating the end-to-end (e2e) container-based tests located in the `toolkit` directory.
