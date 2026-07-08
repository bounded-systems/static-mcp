---
bump: patch
---
Build the tool surface on @bounded-systems/verbspec-mcp (the generic base) instead of a hand-rolled registerTool loop — static-mcp is now a topic layer that injects its verifying client via the base's `deps` seam and shapes verified results via `mapResult`, keeping resources, verification, CLI, and HTTP. Public API and behavior are unchanged.
