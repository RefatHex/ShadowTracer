"""Phase 7.7: analyst-triggered, read-only LLM investigation agent (FEATURE_PLAN.md §7.7).

A deterministic pipeline, not an autonomous agent: evidence is gathered IN CODE from the same
tenant-scoped, authz-checked read APIs the analyst already has; the local LLM only writes a summary
from that evidence and may request at most 2 more read-only tools from a fixed list; a verify step in
code checks every cited claim. The agent has NO state-changing tool. See agent.py for the flow.
"""
