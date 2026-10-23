"""entra-mcp: read-only MCP server for Microsoft Entra ID and Intune over Microsoft Graph v1.0.

Milestone 1. One request path: MCP client -> tool registry (schemas) -> policy gate (allowlist + target
guard) -> Graph client (app-only token) -> audit log. No tool takes a URL or a Graph path.
"""
__version__ = "0.1.0"
