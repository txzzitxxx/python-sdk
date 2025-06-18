# MCP OAuth Authentication Demo

This example demonstrates OAuth 2.0 authentication with the Model Context Protocol using **separate Authorization Server (AS) and Resource Server (RS)** to comply with the new RFC 9728 specification.

---

## Setup Requirements

**Create a GitHub OAuth App:**
- Go to GitHub Settings > Developer settings > OAuth Apps > New OAuth App
- **Authorization callback URL:** `http://localhost:9000/github/callback`
- Note down your **Client ID** and **Client Secret**

**Set environment variables:**
```bash
export MCP_GITHUB_CLIENT_ID="your_client_id_here"  
export MCP_GITHUB_CLIENT_SECRET="your_client_secret_here"
```

---

## Running the Servers

### Step 1: Start Authorization Server

```bash
# Navigate to the simple-auth directory
cd /Users/inna/code/mcp/python-sdk/examples/servers/simple-auth

# Start Authorization Server on port 9000
python -m mcp_simple_auth.auth_server --port=9000
```

**What it provides:**
- OAuth 2.0 flows (registration, authorization, token exchange)
- GitHub OAuth integration for user authentication
- Token introspection endpoint for Resource Servers (`/introspect`)
- User data proxy endpoint (`/github/user`)

---

### Step 2: Start Resource Server (MCP Server)

```bash
# In another terminal, navigate to the simple-auth directory
cd /Users/inna/code/mcp/python-sdk/examples/servers/simple-auth

# Start Resource Server on port 8001, connected to Authorization Server
python -m mcp_simple_auth.server --port=8001 --auth-server=http://localhost:9000  --transport=streamable-http
```


### Step 3: Test with Client

```bash
# Start Resource Server with streamable HTTP
python -m mcp_simple_auth.server --port=8001 --auth-server=http://localhost:9000 --transport=streamable-http

# Start client with streamable HTTP  
MCP_SERVER_PORT=8001 MCP_TRANSPORT_TYPE=streamable_http python -m mcp_simple_auth_client.main
```


## How It Works

### RFC 9728 Discovery

**Client → Resource Server:**
```bash
curl http://localhost:8001/.well-known/oauth-protected-resource
```
```json
{
  "resource": "http://localhost:8001",
  "authorization_servers": ["http://localhost:9000"]
}
```

**Client → Authorization Server:**
```bash
curl http://localhost:9000/.well-known/oauth-authorization-server
```
```json
{
  "issuer": "http://localhost:9000",
  "authorization_endpoint": "http://localhost:9000/authorize",
  "token_endpoint": "http://localhost:9000/token"
}
```

## Manual Testing

### Test Discovery
```bash
# Test Resource Server discovery endpoint
curl -v http://localhost:8001/.well-known/oauth-protected-resource

# Test Authorization Server metadata
curl -v http://localhost:9000/.well-known/oauth-authorization-server
```

### Test Token Introspection
```bash
# After getting a token through OAuth flow:
curl -X POST http://localhost:9000/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=your_access_token"
```
