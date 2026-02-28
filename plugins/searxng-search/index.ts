// OpenClaw plugin: searxng-search
// Registers a searxng_search tool as fallback when Brave Search quota is depleted.

export default function register(api) {
  const pluginConfig = api.pluginConfig || {};
  const baseUrl = (pluginConfig.baseUrl as string) || "http://searxng:8080";
  const defaultMaxResults = (pluginConfig.maxResults as number) || 5;

  api.registerTool({
    name: "searxng_search",
    label: "SearXNG Search",
    description:
      "Search the web using the local SearXNG meta-search engine. " +
      "Use this as a fallback when web_search fails due to API quota limits (HTTP 429) " +
      "or when web_search is unavailable.",
    parameters: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "The search query.",
        },
        count: {
          type: "number",
          description: "Number of results (1-10, default 5).",
          minimum: 1,
          maximum: 10,
        },
        language: {
          type: "string",
          description: "Search language as BCP-47 code (e.g. 'en', 'de'). Default: auto.",
        },
      },
      required: ["query"],
    },

    async execute(_toolCallId, args) {
      const params = args as Record<string, unknown>;
      const query = typeof params.query === "string" ? params.query.trim() : "";
      if (!query) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: "missing_query",
                message: "query parameter is required",
              }),
            },
          ],
        };
      }

      const count = Math.max(
        1,
        Math.min(10, Math.floor(Number(params.count) || defaultMaxResults)),
      );
      const language =
        typeof params.language === "string" ? params.language.trim() : "";

      const url = new URL("/search", baseUrl);
      url.searchParams.set("q", query);
      url.searchParams.set("format", "json");
      url.searchParams.set("pageno", "1");
      if (language) {
        url.searchParams.set("language", language);
      }

      const start = Date.now();

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15_000);

        const res = await fetch(url.toString(), {
          method: "GET",
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (!res.ok) {
          const body = await res.text().catch(() => "");
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  error: "searxng_error",
                  status: res.status,
                  message: body || res.statusText,
                }),
              },
            ],
          };
        }

        const data = await res.json();
        const allResults = Array.isArray(data.results) ? data.results : [];
        const results = allResults.slice(0, count).map((r) => ({
          title: r.title || "",
          url: r.url || "",
          description: r.content || "",
          engine: r.engine || undefined,
          publishedDate: r.publishedDate || undefined,
        }));

        const payload = {
          query,
          provider: "searxng",
          count: results.length,
          tookMs: Date.now() - start,
          results,
        };

        return {
          content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: "searxng_fetch_failed",
                message,
                hint: "Is the searxng Docker service running? Check: docker compose ps",
              }),
            },
          ],
        };
      }
    },
  });
}
