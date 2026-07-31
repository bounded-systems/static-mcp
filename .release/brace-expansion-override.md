---
bump: patch
---
Clear the last dependency advisories: `@modelcontextprotocol/sdk` moves to `^1.30.0` (taking `@hono/node-server` to 2.0.12 and `fast-uri` to 3.1.4), and `brace-expansion` is promoted to a direct import at `^5.0.8` so the resolver cannot keep a stale 5.0.6 that carried GHSA-3jxr-9vmj-r5cp and GHSA-mh99-v99m-4gvg. No public API change.
