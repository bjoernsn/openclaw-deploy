# Safety Concept — OpenClaw Local Deployment

> Audit date: 2026-02-21

## Overview

This repository provides a hardened Docker Compose wrapper around [OpenClaw](https://github.com/openclaw/openclaw) for local use as an LLM agent orchestrator. The design goals are:

- One-command start with minimal configuration
- Non-root, read-only container with no host privileges
- Secrets never committed to version control
- Localhost-only network exposure by default
- Optional egress restriction for high-security environments

---

## Container hardening

| Control | Implementation | File |
|---------|---------------|------|
| Non-root execution | `user: 1000:1000` (node user from base image) | docker-compose.yml |
| Read-only filesystem | `read_only: true`; only `/home/node/.openclaw` and `/tmp` writable | docker-compose.yml |
| No privilege escalation | `security_opt: [no-new-privileges:true]` | docker-compose.yml |
| All capabilities dropped | `cap_drop: [ALL]` | docker-compose.yml |
| No Docker socket | Not mounted — container cannot control host daemon | docker-compose.yml |
| No privileged mode | Not set | docker-compose.yml |
| No host networking | Uses isolated bridge network | docker-compose.yml |
| Init process (PID 1) | `init: true` — proper signal handling and zombie reaping | docker-compose.yml |
| Resource limits | 2 CPU / 2 GB RAM cap, 512 MB reservation | docker-compose.yml |
| tmpfs for temp files | `/tmp` mounted as tmpfs (256 MB, sticky bit 1777) | docker-compose.yml |
| Healthcheck | Internal `127.0.0.1` fetch every 30s, no credentials exposed | docker-compose.yml |

### Custom image layer

The Dockerfile extends the upstream OpenClaw image with data analysis tools (Python, psycopg2, pandas, numpy, sqlalchemy, postgresql-client, jq). Security measures in the build:

- `--no-install-recommends` to minimize installed packages
- pip is purged after installation (`apt-get purge -y python3-pip`)
- apt cache and pip cache cleaned (`rm -rf /var/lib/apt/lists/* /root/.cache`)
- Returns to non-root user (`USER 1000:1000`) after privileged install step

### Init container

A one-shot `busybox` container (`init-permissions`) runs `chown -R 1000:1000 /data` on the named volume to ensure the non-root service can write on first run. It uses `restart: "no"` and exits immediately.

---

## Secrets management

| Measure | Detail |
|---------|--------|
| `.env` is git-ignored | `.gitignore` covers `.env`, `.env.local`, `.env.*.local` |
| `.env.example` has no real values | Committed as a template only |
| Git history is clean | No secrets have ever been committed (verified via `git log --diff-filter=A`) |
| Token generated via CSPRNG | `openssl rand -hex 32` with Python `secrets` fallback (192 bits of entropy) |

### Recommendation

Run `chmod 600 .env` after creation to prevent other local users from reading API keys. Consider adding this to `scripts/bootstrap.sh`.

---

## Authentication

The OpenClaw gateway supports multiple auth modes. This deployment uses **token auth**.

### Token auth flow

1. Client connects via WebSocket and provides `connect.auth.token`
2. Gateway compares using `timingSafeEqual` (Node.js crypto) to prevent timing attacks
3. Failed attempts are rate-limited per IP (`src/gateway/auth-rate-limit.ts`)
4. On mismatch, connection is rejected with reason `token_mismatch`

### Token entropy

The bootstrap script generates 32 random bytes → 48 hex characters → **192 bits of entropy**. This exceeds the 128-bit threshold considered secure for bearer tokens.

### LAN bind safety guard

The upstream code refuses to start with `--bind lan` if no authentication is configured:

```
Refusing to bind gateway to lan without auth...
```

This prevents accidental unauthenticated LAN exposure.

---

## Network exposure

### Default posture

Ports are bound to `127.0.0.1` only:

```yaml
ports:
  - "127.0.0.1:${OPENCLAW_HOST_PORT:-3210}:18789"
```

The gateway is unreachable from other machines on the network.

### Container bind mode

The gateway starts with `--bind lan` (listens on `0.0.0.0` inside the container). This is safe because the Docker port mapping restricts access to localhost. However, if the port binding is ever changed to `0.0.0.0:3210:18789`, the gateway becomes LAN-exposed.

**Recommendation:** Consider switching to `--bind loopback` for defense-in-depth, unless LAN/Tailscale access is needed.

### Egress (outbound)

The Docker network is set to `internal: false` (default), allowing the container to make outbound connections. This is required for LLM API calls.

For restricted environments, the README documents two egress lockdown options:
- **Option A:** Internal Docker network + Squid proxy allowlisting only LLM API domains
- **Option B:** Host firewall rules (iptables/ufw) restricting the Docker bridge subnet

---

## Agent execution risks

### Node tool (remote command execution)

The OpenClaw `nodes` tool can execute arbitrary shell commands on paired devices via the `system.run` action. Mitigations:

- Requires device to be paired and registered with the gateway
- Commands on approval-required nodes need explicit user consent via the UI
- Commands execute on the remote node, not on the OpenClaw server
- Gateway authentication is required before any node interaction

### Plugin trust boundary

Plugins run **in-process** with full OpenClaw privileges. There is no runtime sandbox. Only install plugins from trusted sources.

### Recommended OpenClaw configuration flags

Set these in the OpenClaw config (`~/.openclaw/openclaw.json` inside the volume) for additional hardening:

```json
{
  "tools": {
    "exec": {
      "applyPatch": { "workspaceOnly": true }
    },
    "fs": {
      "workspaceOnly": true
    }
  }
}
```

This restricts agent file operations to the workspace directory.

---

## Threat model

### Protected against

| Threat | Mitigation |
|--------|-----------|
| Casual network exposure | Ports bound to 127.0.0.1 only |
| Container → host privilege escalation | Non-root, no caps, no-new-privileges, no Docker socket |
| Leaked secrets in git | `.env` is git-ignored; only `.env.example` is committed |
| Unbounded resource consumption | CPU/memory limits prevent runaway processes |
| Filesystem tampering | Read-only root; only data volume + tmpfs are writable |
| Timing attacks on auth | `timingSafeEqual` for token comparison |
| Brute-force auth | Rate limiting on failed attempts |

### NOT protected against

| Threat | Notes |
|--------|-------|
| Compromised API keys | If the container is breached, keys in memory are extractable. Rotate on suspicion. |
| Malicious agent output | A jailbroken model with dangerous tools enabled could instruct harmful actions. Audit tool permissions. |
| Supply-chain attacks | Docker image is built from source. Pin git commits for reproducibility. |
| Host-level compromise | Container isolation is moot if the host is compromised. |
| Outbound data exfiltration | Default mode allows internet access. Use egress restriction to mitigate. |
| Plugin compromise | Plugins are unsandboxed. Only install trusted plugins. |

---

## Audit findings

### No critical or high-priority issues found.

### Medium

1. **`--bind lan` inside container** (`docker-compose.yml:100`)
   The gateway listens on all interfaces inside the container. Safe today due to localhost port mapping, but fragile if the mapping changes. Consider `--bind loopback`.

2. **`.env` file permissions**
   File is mode `0644` (world-readable). Other local users can read API keys. Fix: `chmod 600 .env` and add to `bootstrap.sh`.

### Low

3. **`busybox:latest` unpinned** (`docker-compose.yml:15`)
   Pin to a specific version (e.g., `busybox:1.37`) for reproducible builds.

4. **`--allow-unconfigured` flag** (`docker-compose.yml:99`)
   Bypasses config validation. Remove once configuration is stable.

5. **Redundant `OLLAMA_API_BASE` in `.env`**
   Overridden by the `environment:` block in `docker-compose.yml`. Not a security issue; just unnecessary.

---

## Upstream requirements

- **Node.js 22.12.0+** required per OpenClaw's `SECURITY.md` (patches for CVE-2025-59466, CVE-2026-21636)
- Web UI is **not hardened for public internet** — keep localhost-only
- Review agent tool permissions in the OpenClaw UI regularly
