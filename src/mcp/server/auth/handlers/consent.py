from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.provider import OAuthAuthorizationServerProvider


@dataclass
class ConsentHandler:
    provider: OAuthAuthorizationServerProvider[Any, Any, Any]

    async def handle(self, request: Request) -> Response:
        # This handles both showing the consent form (GET) and processing consent (POST)

        if request.method == "GET":
            # Show consent form
            return await self._show_consent_form(request)
        elif request.method == "POST":
            # Process consent
            return await self._process_consent(request)
        else:
            return HTMLResponse(status_code=405, content="Method not allowed")

    async def _show_consent_form(self, request: Request) -> HTMLResponse:
        client_id = request.query_params.get("client_id", "")
        redirect_uri = request.query_params.get("redirect_uri", "")
        state = request.query_params.get("state", "")
        scopes = request.query_params.get("scopes", "")
        code_challenge = request.query_params.get("code_challenge", "")
        response_type = request.query_params.get("response_type", "")

        # Get client info to display client_name
        client_name = client_id  # Default to client_id if we can't get the client
        if client_id:
            client = await self.provider.get_client(client_id)
            if client and hasattr(client, 'client_name'):
                client_name = client.client_name

        # TODO: get this passed in
        target_url = "/consent"

        # Create a simple consent form

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Required</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .consent-form {{
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }}
        h1 {{
            margin: 0 0 20px 0;
            font-size: 24px;
            font-weight: 600;
        }}
        p {{
            margin-bottom: 20px;
            color: #666;
        }}
        .client-info {{
            background: #f8f8f8;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }}
        .scopes {{
            margin-bottom: 20px;
        }}
        .scope-item {{
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }}
        .scope-item:last-child {{
            border-bottom: none;
        }}
        .button-group {{
            display: flex;
            gap: 10px;
        }}
        button {{
            flex: 1;
            padding: 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }}
        .approve {{
            background: #0366d6;
            color: white;
        }}
        .deny {{
            background: #f6f8fa;
            color: #24292e;
            border: 1px solid #d1d5da;
        }}
        button:hover {{
            opacity: 0.9;
        }}
    </style>
</head>
<body>
    <div class="consent-form">
        <h1>Authorization Request</h1>
        <p>The application <strong>{client_name}</strong> is requesting access to your resources.</p>

        <div class="client-info">
            <strong>Application Name:</strong> {client_name}<br>
            <strong>Client ID:</strong> {client_id}<br>
            <strong>Redirect URI:</strong> {redirect_uri}
        </div>

        <div class="scopes">
            <strong>Requested Permissions:</strong>
            {self._format_scopes(scopes)}
        </div>

        <form method="POST" action="{target_url}">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="state" value="{state}">
            <input type="hidden" name="scopes" value="{scopes}">
            <input type="hidden" name="code_challenge" value="{code_challenge}">
            <input type="hidden" name="response_type" value="{response_type}">

            <div class="button-group">
                <button type="submit" name="action" value="approve" class="approve">Approve</button>
                <button type="submit" name="action" value="deny" class="deny">Deny</button>
            </div>
        </form>
    </div>
</body>
</html>
"""
        return HTMLResponse(content=html_content)

    async def _process_consent(self, request: Request) -> RedirectResponse:
        form_data = await request.form()
        action = form_data.get("action")

        if action == "approve":
            # Grant consent and continue with authorization
            client_id = form_data.get("client_id")
            if client_id:
                client = await self.provider.get_client(client_id)
                if client:
                    await self.provider.grant_client_consent(client)

            # Redirect back to authorization endpoint with original parameters
            auth_params = urlencode({
                k: v for k, v in form_data.items()
                if k in ["client_id", "redirect_uri", "state", "scopes", "code_challenge", "response_type"]
            })

            return RedirectResponse(
                # TODO: get this passed in
                url=f"/authorize?{auth_params}",
                status_code=302,
                headers={"Cache-Control": "no-store"},
            )
        else:
            # User denied consent
            redirect_uri = form_data.get("redirect_uri")
            state = form_data.get("state")

            error_params = {
                "error": "access_denied",
                "error_description": "User denied the authorization request"
            }
            if state:
                error_params["state"] = state

            if redirect_uri:
                return RedirectResponse(
                    url=f"{redirect_uri}?{urlencode(error_params)}",
                    status_code=302,
                    headers={"Cache-Control": "no-store"},
                )
            else:
                return HTMLResponse(
                    status_code=400,
                    content=f"Access denied: {error_params['error_description']}"
                )

    def _format_scopes(self, scopes: str) -> str:
        if not scopes:
            return "<p>No specific permissions requested</p>"

        scope_list = scopes.split()
        if not scope_list:
            return "<p>No specific permissions requested</p>"

        scope_html = ""
        for scope in scope_list:
            scope_html += f'<div class="scope-item">{scope}</div>'

        return scope_html
