# OpenClaw Deploy — Architecture & Safety Design

## System Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│  HOST MACHINE                                                           │
│                                                                         │
│  ┌──────────┐   ┌──────────────────────────────────────────────────┐    │
│  │  Ollama   │   │  Docker Engine                                   │    │
│  │ (GPU LLM) │   │                                                  │    │
│  │ :11434    │   │  ┌─────────────────────────────────────────────┐ │    │
│  └─────┬────┘   │  │  openclaw-internal network (bridge)         │ │    │
│        │        │  │                                              │ │    │
│        │        │  │  ┌───────────────────┐  ┌───────────────┐   │ │    │
│        │        │  │  │ openclaw-gateway   │  │ searxng        │   │ │    │
│        │        │  │  │ (THE AGENT)        │  │ :8080          │   │ │    │
│        │        │  │  │                    │  │ meta-search    │   │ │    │
│        │        │  │  │ user: 1000:1000    ├──┤ (no host port) │   │ │    │
│        │        │  │  │ read_only: true    │  └───────┬───────┘   │ │    │
│        │        │  │  │ cap_drop: ALL      │          │           │ │    │
│        │        │  │  │ no-new-privileges  │  ┌───────┴───────┐   │ │    │
│        │        │  │  │ no docker socket   │  │ valkey         │   │ │    │
│        │        │  │  │ 2 CPU / 2G RAM     │  │ :6379          │   │ │    │
│        │        │  │  │                    │  │ (cache)        │   │ │    │
│        │        │  │  │ :18789 → :3210     │  │ (no host port) │   │ │    │
│        │        │  │  │ (localhost only)   │  └───────────────┘   │ │    │
│        │        │  │  └────────┬───────────┘                      │ │    │
│        │        │  │           │                                   │ │    │
│        │        │  └───────────┼───────────────────────────────────┘ │    │
│        │        │              │ stdout/stderr                       │    │
│        │        │              ▼                                     │    │
│        │        │  ┌───────────────────────┐                        │    │
│        │        │  │ openclaw-observer      │                        │    │
│        │        │  │ (WATCHDOG)             │                        │    │
│        │        │  │                        │     ┌──────────────┐   │    │
│        │        │  │ NOT on agent network   │     │ Docker Socket │   │    │
│        │◄───────┼──┤ Reads logs via socket  ├────►│ /var/run/     │   │    │
│        │        │  │ Can stop agent         │     │ docker.sock   │   │    │
│        │        │  │ 0.5 CPU / 256M RAM     │     └──────────────┘   │    │
│        │        │  │                        │                        │    │
│        │        │  └───────────┬────────────┘                        │    │
│        │        │              │                                     │    │
│        │        └──────────────┼─────────────────────────────────────┘    │
│        │                       │                                         │
│  ┌─────┴───────────────────────┴──────────────────────────────────────┐  │
│  │  INTERNET                                                          │  │
│  │                                                                    │  │
│  │  ┌──────────┐  ┌──────────────┐  ┌─────────────┐  ┌───────────┐  │  │
│  │  │ Telegram  │  │ LLM APIs     │  │ Brave Search│  │ Search    │  │  │
│  │  │ Bot API   │  │ (Anthropic,  │  │ API         │  │ engines   │  │  │
│  │  │           │  │  OpenRouter,  │  │             │  │ (via      │  │  │
│  │  │           │  │  Gemini)      │  │             │  │  SearXNG) │  │  │
│  │  └─────┬─────┘  └──────────────┘  └─────────────┘  └───────────┘  │  │
│  └────────┼──────────────────────────────────────────────────────────┘  │
│           │                                                             │
│           ▼                                                             │
│  ┌──────────────┐                                                       │
│  │ YOUR PHONE   │  ◄── Alerts, approval requests, lockdown notices      │
│  │ (Telegram)   │                                                       │
│  └──────────────┘                                                       │
└─────────────────────────────────────────────────────────────────────────┘
```

## Security Layers

```
Layer 0: CONTAINER SANDBOX (hard boundary)
├── read-only root filesystem
├── non-root user (1000:1000)
├── all capabilities dropped
├── no-new-privileges
├── no Docker socket
├── resource limits (2 CPU, 2G RAM)
└── tmpfs for /tmp only (256M)

Layer 1: NETWORK ISOLATION
├── Agent on openclaw-internal bridge
├── SearXNG/Valkey internal-only (no host ports)
├── Gateway port bound to 127.0.0.1 only
├── Observer on separate default network
└── ⚠ Agent has internet access (internal: false)

Layer 2: OBSERVER WATCHDOG (this system)
├── Pattern-based log pre-filter (regex)
├── LLM evaluation via local Ollama
├── Telegram alerts (WARN level)
├── Auto-lockdown (CRITICAL level)
└── Fail-closed on consecutive LLM failures

Layer 3: AGENT INSTRUCTION GUARDRAILS (soft boundary)
├── AGENTS.md: Email Approval Protocol
├── TOOLS.md: Outbound Communication rules
└── Telegram approval gate for external actions
```

## Watchdog Decision Flow

```
Container Log Stream
        │
        ▼
┌───────────────────┐
│ Read log line      │
│ (stdout + stderr)  │
└───────┬───────────┘
        │
        ▼
┌───────────────────┐     YES    ┌─────────────────────┐
│ Critical pattern?  ├──────────►│ IMMEDIATE:           │
│ (reverse shell,    │           │ 1. Telegram alert    │
│  docker socket,    │           │ 2. Container stop    │
│  pipe-to-shell)    │           │ 3. Exit observer     │
└───────┬───────────┘           └─────────────────────┘
        │ NO
        ▼
┌───────────────────┐     YES    ┌─────────────────────┐
│ Suspicious pattern?├──────────►│ Add to priority      │
│ (email, secrets,   │           │ buffer by category   │
│  escalation, etc.) │           └──────────┬──────────┘
└───────┬───────────┘                       │
        │ NO                                │
        ▼                                   ▼
┌───────────────────┐           ┌─────────────────────┐
│ Continue to next   │           │ Batch ready?         │
│ log line           │           │ (≥10 items OR        │
└───────────────────┘           │  ≥10s timeout)       │
                                └──────────┬──────────┘
                                           │ YES
                                           ▼
                                ┌─────────────────────┐
                                │ Send to Ollama LLM   │
                                │ for evaluation        │
                                └──────────┬──────────┘
                                           │
                                ┌──────────┴──────────┐
                                │                      │
                          ┌─────┴─────┐         ┌──────┴─────┐
                          │ LLM says  │         │ LLM says   │
                          │ CRITICAL  │         │ WARN       │
                          │           │         │            │
                          │ Telegram  │         │ Telegram   │
                          │ + stop    │         │ alert only │
                          └───────────┘         └────────────┘

                          ┌────────────┐        ┌────────────┐
                          │ LLM says   │        │ LLM failed │
                          │ SAFE       │        │ (3x in row)│
                          │            │        │            │
                          │ Log only,  │        │ FAIL-CLOSED│
                          │ no action  │        │ Telegram + │
                          └────────────┘        │ lockdown   │
                                                └────────────┘
```

## Container Inventory

| Container | Purpose | Network | Docker Socket | User | Ports |
|-----------|---------|---------|---------------|------|-------|
| openclaw-gateway | AI agent (the thing we're watching) | openclaw-internal | **NO** | 1000:1000 | 127.0.0.1:3210 |
| openclaw-observer | Watchdog (monitors the agent) | observer-net (isolated) | **No raw socket** (via docker-socket-proxy) | 1000:1000 | none |
| openclaw-searxng | Fallback search engine | openclaw-internal | NO | non-root | none (internal) |
| openclaw-valkey | Cache for SearXNG | openclaw-internal | NO | non-root | none (internal) |
| init-permissions | One-shot volume setup | none | NO | root | none |

## File Layout

```
openclaw-deploy/
├── docker-compose.yml      # Orchestration for all services
├── Dockerfile              # Custom agent image (adds Python, psql, etc.)
├── .env                    # Secrets (git-ignored)
├── .gitignore
├── ARCHITECTURE.md         # This file
├── SAFETY_AUDIT.md         # Security audit findings
│
├── observer/               # Watchdog service
│   ├── Dockerfile
│   ├── observer.py         # Main monitoring script
│   └── requirements.txt
│
├── plugins/                # OpenClaw plugins
│   └── searxng-search/
│       ├── openclaw.plugin.json
│       └── index.ts
│
├── searxng/                # SearXNG configuration
│   └── settings.yml
│
└── workspace/              # Agent workspace (bind-mounted, git-ignored)
    ├── AGENTS.md           # Agent behavior instructions
    ├── TOOLS.md            # Tool usage instructions
    └── ...                 # Agent-created files
```

## Trust Boundaries

```
TRUSTED (our code, we control):
├── docker-compose.yml
├── observer/observer.py
├── Dockerfile
├── .env
└── Host machine (Ollama, Docker Engine)

UNTRUSTED (agent-controlled):
├── Everything inside openclaw-gateway container
├── workspace/ contents (agent can write anything here)
├── Agent's conversation output / logs
└── Agent's tool invocations

SEMI-TRUSTED (third-party services):
├── Ollama model output (can be manipulated by agent via prompts)
├── SearXNG search results
├── External LLM API responses
└── Telegram Bot API
```

## Known Limitations

1. **Log-based monitoring is bypassable** — An adversarial LLM can encode, obfuscate, or simply avoid logging suspicious actions. The observer is a heuristic layer, not a security boundary.

2. **The real security boundary is the container sandbox** (Layer 0). The observer (Layer 2) adds defense-in-depth but should not be relied upon as the sole protection.

3. **The agent has internet access** — Network-level data exfiltration (HTTPS POST, DNS tunneling, WebSocket) is not caught by log monitoring. Set `internal: true` on the network and use an allowlist proxy for full egress control.

4. **The LLM evaluator can be prompt-injected** — Agent log output is untrusted input fed directly to the evaluator. The observer uses role-separated chat API and sanitization to mitigate, but a sufficiently clever agent may still manipulate verdicts.

5. **Telegram bot separation** — The observer uses a dedicated `OBSERVER_TELEGRAM_BOT_TOKEN`, separate from the agent's bot. This prevents the agent from interfering with security notifications.
