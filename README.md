# Remote access gateway

Self-hosted, memory-safe remote access workspace: a single Rust gateway that terminates SSH, VNC and RDP
sessions server-side and streams them to a keyboard-driven browser workspace over binary WebSockets.
Target credentials and node details are kept in a per-user, zero-plaintext vault.

> Status: early development (workspace scaffold). Not usable yet.

The product name is defined only in [`branding.toml`](branding.toml).

## Layout

| Path | Contents |
|---|---|
| `crates/gateway` | Server binary: HTTP API, workspace socket, vault keyring, protocol multiplexer |
| `crates/vault` | Cryptography and zeroizing secret types (no I/O) |
| `crates/protocol-core` | Browser wire framing and SSH/VNC/RDP engines |
| `crates/edge-proto` | Edge-runner tunnel message types |
| `web/` | SvelteKit (Svelte 5, TypeScript, Tailwind v4) single-page workspace |
| `dev/targets/` | Disposable test targets used by `docker-compose.dev.yml` |

## Development

Requirements: Rust (stable, edition 2024), Node 24+, pnpm 12, Docker with Compose.

```bash
# test targets (SSH on 127.0.0.1:2222, user devuser / devpass)
docker compose -f docker-compose.dev.yml up -d --build

# gateway (plain HTTP is only allowed on loopback)
cargo run -p gateway -- --tls-mode plaintext-dev

# web workspace dev server on http://127.0.0.1:5173 (proxies /api to the gateway)
cd web && pnpm install && pnpm dev
```

Checks: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, `cargo deny check`, `cd web && pnpm check && pnpm test && pnpm build`.

## License

[AGPL-3.0-only](LICENSE).
