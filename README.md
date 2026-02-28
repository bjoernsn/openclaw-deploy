# OpenClaw Deploy

Hardened Docker Compose setup for running [OpenClaw](https://github.com/openclaw/openclaw) locally with container sandboxing, an AI-powered security watchdog, and self-hosted fallback search.

## Features

- **One-command start** — `./scripts/bootstrap.sh` then `./scripts/up.sh`
- **Container hardening** — non-root, read-only filesystem, all capabilities dropped, no Docker socket
- **Observer watchdog** — external container monitors agent logs, flags suspicious behavior with a local LLM, sends Telegram alerts, can auto-lockdown
- **Self-hosted search** — SearXNG meta-search engine as free fallback when Brave API quota runs out
- **Localhost-only ports** — nothing exposed to the LAN by default
- **Easy LLM swapping** — cloud APIs (Anthropic, OpenAI, Google, OpenRouter) or local models (Ollama, vLLM)

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  HOST                                                          │
│                                                                │
│  ┌──────────┐   Docker Engine                                  │
│  │  Ollama   │   ┌──────────────────────────────────────────┐  │
│  │ (GPU LLM) │   │  openclaw-internal network               │  │
│  │ :11434    │   │                                          │  │
│  └─────┬────┘   │  ┌──────────────┐  ┌──────┐  ┌───────┐  │  │
│        │        │  │ openclaw     │  │searxng│  │valkey │  │  │
│        │        │  │ (THE AGENT)  │  │ :8080 │  │ :6379 │  │  │
│        │        │  │ non-root     │  │ meta- │  │ cache │  │  │
│        │        │  │ read-only    │  │ search│  │       │  │  │
│        │        │  │ no caps      │  └───────┘  └───────┘  │  │
│        │        │  │ :3210→:18789 │                         │  │
│        │        │  └──────┬───────┘                         │  │
│        │        └─────────┼─────────────────────────────────┘  │
│        │                  │ stdout/stderr                       │
│        │                  ▼                                     │
│        │        ┌──────────────────┐                           │
│        │◄───────┤ observer         │──► Docker Socket          │
│        │        │ (WATCHDOG)       │──► Telegram alerts         │
│        │        │ NOT on agent net │                           │
│        │        └──────────────────┘                           │
└────────────────────────────────────────────────────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full diagram, security layers, and watchdog decision flow.

## Quick Start

### Prerequisites

- Docker & Docker Compose v2
- Git clone of the [OpenClaw source](https://github.com/openclaw/openclaw)
- At least one LLM API key (Anthropic, OpenAI, Google, or OpenRouter)
- (Optional) [Ollama](https://ollama.ai) on the host for the observer watchdog

### Setup

```bash
# 1. Clone this repo
git clone https://github.com/your-user/openclaw-deploy.git
cd openclaw-deploy

# 2. Bootstrap — creates .env, generates tokens
./scripts/bootstrap.sh

# 3. Edit .env — set OPENCLAW_SRC_DIR and add at least one LLM API key
$EDITOR .env

# 4. Copy workspace templates (first time only)
cp workspace-template/* workspace/

# 5. Start everything
./scripts/up.sh

# 6. Open the UI
open http://127.0.0.1:3210
```

### Verify

```bash
docker compose ps                      # all services healthy
curl -s http://127.0.0.1:3210/health   # returns OK / 200
docker compose logs -f                 # stream all logs
```

### Stop

```bash
./scripts/down.sh
# Data volume "openclaw-data" is preserved. To destroy:
# docker volume rm openclaw-data openclaw-valkey-data
```

## Services

| Container | Purpose | Network | User | Ports |
|-----------|---------|---------|------|-------|
| `openclaw-gateway` | AI agent (OpenClaw) | openclaw-internal | 1000:1000 | 127.0.0.1:3210 |
| `openclaw-observer` | Security watchdog | observer-net (isolated) | non-root (uid 1000) | none |
| `openclaw-searxng` | Fallback search engine | openclaw-internal | non-root | none (internal) |
| `openclaw-valkey` | Cache for SearXNG | openclaw-internal | non-root | none (internal) |
| `init-permissions` | One-shot volume setup | none | root | none |

## LLM Configuration

### Cloud Providers

Set the relevant key(s) in `.env`:

| Provider | Variable |
|----------|----------|
| Anthropic | `ANTHROPIC_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| Google | `GEMINI_API_KEY` |
| OpenRouter | `OPENROUTER_API_KEY` |

Configure the default model in the OpenClaw web UI or by editing `openclaw.json` inside the data volume.

### Local LLM

Run any OpenAI-compatible server (Ollama, vLLM, llama.cpp) on the host:

```env
# .env
OLLAMA_API_BASE=http://host.docker.internal:11434
OLLAMA_API_KEY=not-needed
```

`host.docker.internal` resolves to the host on Docker Desktop. On Linux, the compose file already includes `extra_hosts` for this.

## Observer Watchdog

The observer is an external container that monitors the agent for suspicious behavior. It runs **outside** the agent's network and has no API access to the agent.

### How It Works

1. **Log streaming** — reads agent container stdout/stderr via the Docker socket
2. **Pattern matching** — regex pre-filter catches critical patterns (reverse shells, Docker socket access, pipe-to-shell) for immediate lockdown
3. **LLM evaluation** — suspicious-but-not-critical patterns are batched and evaluated by a local Ollama model
4. **Alerts** — sends Telegram messages for warnings; auto-stops the agent container for critical findings
5. **Fail-closed** — if Ollama is unreachable 3 times in a row, the observer assumes the worst and locks down

### Setup

1. Install [Ollama](https://ollama.ai) on the host and pull a model:
   ```bash
   ollama pull qwen2.5:14b
   ```

2. Create a separate Telegram bot for observer alerts (recommended — keeps alerts separate from the agent's chat):
   ```env
   # .env
   OBSERVER_TELEGRAM_BOT_TOKEN=your-admin-bot-token
   OBSERVER_TELEGRAM_CHAT_ID=your-chat-id
   ```

3. The observer starts automatically with `docker compose up -d`.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `OBSERVER_MODEL` | `qwen2.5:14b` | Ollama model for log evaluation |
| `OBSERVER_AUTO_LOCKDOWN` | `true` | Auto-stop agent on CRITICAL findings |
| `OBSERVER_TELEGRAM_BOT_TOKEN` | — | Telegram bot token for alerts |
| `OBSERVER_TELEGRAM_CHAT_ID` | — | Telegram chat ID for alerts |

### Disabling the Observer

To run without the observer, comment it out in `docker-compose.yml` or use a profile override.

See [SAFETY_AUDIT.md](SAFETY_AUDIT.md) for the full security audit of the watchdog system.

## SearXNG Fallback Search

A self-hosted [SearXNG](https://docs.searxng.org/) instance runs on the internal Docker network as a fallback when the Brave Search API quota is depleted.

- No host ports exposed — only reachable by the agent container
- Uses Valkey (Redis fork) for caching
- The `searxng_search` tool is installed as an OpenClaw plugin via `plugins/searxng-search/`

Agent instructions in `workspace/TOOLS.md` tell the agent to try Brave first, then fall back to SearXNG.

## Workspace Templates

The `workspace-template/` directory contains sanitized starter files that get copied into `workspace/` on first setup:

- **AGENTS.md** — agent behavior rules, safety guardrails, email approval protocol
- **TOOLS.md** — tool usage instructions, search fallback documentation

The `workspace/` directory is bind-mounted into the container and is git-ignored (it contains agent-created files).

## Security

### Defense-in-Depth Layers

```
Layer 0: CONTAINER SANDBOX (hard boundary)
├── read-only root filesystem
├── non-root user (1000:1000)
├── all capabilities dropped
├── no-new-privileges
├── no Docker socket
├── resource limits (2 CPU, 2 GB RAM)
└── tmpfs for /tmp only (256M)

Layer 1: NETWORK ISOLATION
├── Agent on internal bridge network
├── SearXNG/Valkey internal-only (no host ports)
├── Gateway port bound to 127.0.0.1 only
└── Observer on separate network (cannot reach agent API)

Layer 2: OBSERVER WATCHDOG
├── Pattern-based log pre-filter (regex)
├── LLM evaluation via local Ollama
├── Telegram alerts (WARN) / auto-lockdown (CRITICAL)
└── Fail-closed on consecutive LLM failures

Layer 3: AGENT INSTRUCTION GUARDRAILS (soft boundary)
├── AGENTS.md safety rules
├── Email approval protocol (Telegram gate)
└── TOOLS.md outbound communication rules
```

### Egress Restriction

By default, the agent can make outbound connections (needed for LLM API calls). To fully lock down egress:

1. Set the network to internal in `docker-compose.yml`:
   ```yaml
   networks:
     openclaw-internal:
       internal: true
   ```

2. Add a forward-proxy (e.g. Squid) that allowlists only LLM API domains:
   ```yaml
   services:
     egress-proxy:
       image: ubuntu/squid
       networks:
         - openclaw-internal
         - default
       volumes:
         - ./squid.conf:/etc/squid/squid.conf:ro
   ```

3. Configure OpenClaw to use the proxy:
   ```env
   HTTP_PROXY=http://egress-proxy:3128
   HTTPS_PROXY=http://egress-proxy:3128
   ```

### Known Limitations

- Log-based monitoring is bypassable — an adversarial model can obfuscate output. The container sandbox (Layer 0) is the real security boundary.
- The agent has internet access by default. Use egress restriction for full lockdown.
- The LLM evaluator can be prompt-injected via crafted log output (mitigated with role separation).
- The observer needs Docker socket access — use a [socket proxy](https://github.com/Tecnativa/docker-socket-proxy) to restrict API calls.

## File Layout

```
openclaw-deploy/
├── docker-compose.yml          # all services
├── Dockerfile                  # custom agent image (adds Python, psql)
├── .env.example                # template (committed, no secrets)
├── .env                        # real secrets (git-ignored)
├── README.md                   # this file
├── ARCHITECTURE.md             # detailed architecture + diagrams
├── SAFETY_AUDIT.md             # security audit findings
│
├── observer/                   # watchdog service
│   ├── Dockerfile
│   ├── observer.py
│   └── requirements.txt
│
├── plugins/                    # OpenClaw plugins
│   └── searxng-search/
│       ├── openclaw.plugin.json
│       └── index.ts
│
├── searxng/                    # SearXNG config
│   └── settings.yml
│
├── workspace-template/         # starter files for agent workspace
│   ├── AGENTS.md
│   └── TOOLS.md
│
├── workspace/                  # agent workspace (git-ignored, bind-mounted)
│
└── scripts/
    ├── bootstrap.sh            # first-time setup
    ├── up.sh                   # build + start
    └── down.sh                 # stop (preserves data)
```

## Updating

```bash
cd /path/to/openclaw && git pull   # update upstream source
cd /path/to/openclaw-deploy
./scripts/up.sh                    # rebuilds the image
```

## Backing Up

```bash
# Export the named volume
docker run --rm -v openclaw-data:/data -v "$(pwd)":/backup \
  busybox tar czf /backup/openclaw-backup-$(date +%F).tar.gz -C /data .
```

## License

MIT
