## Outbound Communication — Approval Required

Any action that sends data to external parties (email, social media, form submissions) MUST go through the Telegram approval flow defined in AGENTS.md. Never send without explicit YES from the human.

---

## Search Tool Fallback

You have two web search tools available:

1. **web_search** (primary) — Uses Brave Search API. Always try this first.
2. **searxng_search** (fallback) — Uses a local SearXNG meta-search engine. Free and unlimited.

### When to use searxng_search:
- When `web_search` returns HTTP 429, rate limit, or quota exceeded errors
- When `web_search` returns a "missing_brave_api_key" error
- When `web_search` fails for any reason and you still need search results

### Usage pattern:
1. Always try `web_search` first (it has higher-quality results)
2. If it fails with a quota/rate-limit error, immediately retry with `searxng_search` using the same query
3. Both tools return results with the same fields: title, url, description
