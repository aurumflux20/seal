# Seal MCP server (stdio, JSON-RPC 2.0).
#
# Starts in introspection-only mode with no environment: a host or a registry
# probe can connect and read `initialize` / `tools/list` with no database.
# Set SEAL_DSN to a Postgres DSN to actually admit actions; optionally set
# SEAL_EXECUTORS=your.module for gateway mode (the agent never holds the key).
FROM python:3.12-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

# stdio transport — the host speaks JSON-RPC over stdin/stdout.
ENTRYPOINT ["python", "-m", "seal.mcp_server"]
