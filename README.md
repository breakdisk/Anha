# ANHA Protocol — AI Namespace & @ai Handle Architecture

ANHA is an open, decentralized identity layer for AI agents. Every agent gets a
human-readable handle (`@agent.org.ai`) backed by a post-quantum cryptographic
keypair, discoverable over a Kademlia DHT, and verifiable without a central authority.

## This Repository

| Path | Contents |
|---|---|
| `crates/anha-core` | Protocol types — `Handle`, `AgentRecord`, `AccessPolicy`, `CallerProof` and more (Apache-2.0) |
| [Releases](../../releases) | Pre-built `anha` CLI binaries for Linux, macOS, Windows |

## Install the CLI

Download the latest binary from [Releases](../../releases):

| Platform | File |
|---|---|
| Linux x86-64 | `anha-linux-x86_64` |
| macOS arm64 | `anha-macos-arm64` |
| Windows x86-64 | `anha-windows-x86_64.exe` |

```bash
# Linux / macOS
chmod +x anha-linux-x86_64
./anha-linux-x86_64 --help

# Windows (PowerShell)
.\anha-windows-x86_64.exe --help
```

## Use `anha-core` in Your Project

```toml
# Cargo.toml
[dependencies]
anha-core = { git = "https://github.com/breakdisk/Anha" }
```

## Protocol Overview

```
@agent.org.ai
     │
     ▼
 Handle (validated identifier)
     │
     ▼
 AgentRecord (stored in DHT)
   ├── public_key      ML-DSA-65 verifying key (post-quantum)
   ├── kem_public_key  ML-KEM-768 encapsulation key
   ├── addresses       Multiaddrs (libp2p reachability)
   ├── capabilities    What this agent can do
   ├── access_policy   Zero Trust L4 — who may call it
   └── signature       ML-DSA-65 signature over canonical bytes
```

## Key Concepts

- **Handle** — `@<agent>.<org>.ai` identifier, validated by format rules
- **AgentRecord** — the DHT record that maps a handle to reachability + capabilities
- **CallerProof** — signed token an agent presents to prove its identity (Zero Trust L3)
- **KeySupersede** — cryptographic key-rotation proof linking old key → new key
- **AccessPolicy** — `AllowList` or `RequireCapability` guard on who may call an agent

## License

`anha-core` is Apache-2.0. The full ANHA node (DHT, MCP server, CLI) is proprietary.
