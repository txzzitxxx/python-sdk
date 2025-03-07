"""
Handler for OAuth 2.0 Authorization endpoint.

Corresponds to TypeScript file: src/server/auth/handlers/authorize.ts
"""

import re
from urllib.parse import urlparse, urlunparse, urlencode
from typing import Any, Callable, Dict, List, Literal, Optional
from urllib.parse import urlencode, parse_qs

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from pydantic import AnyHttpUrl, AnyUrl, BaseModel, Field, ValidationError
from pydantic_core import Url

from mcp.server.auth.errors import (
    InvalidClientError, 
    InvalidRequestError,
    UnsupportedResponseTypeError,
    ServerError,
    OAuthError,
)
from mcp.server.auth.provider import AuthorizationParams, OAuthServerProvider
from mcp.shared.auth import OAuthClientInformationFull


class AuthorizationRequest(BaseModel):
    """
    Model for the authorization request parameters.
    
    Corresponds to request schema in authorizationHandler in src/server/auth/handlers/authorize.ts
    """
    client_id: str = Field(..., description="The client ID")
    redirect_uri: AnyHttpUrl | None = Field(..., description="URL to redirect to after authorization")

    response_type: Literal["code"] = Field(..., description="Must be 'code' for authorization code flow")
    code_challenge: str = Field(..., description="PKCE code challenge")
    code_challenge_method: Literal["S256"] = Field("S256", description="PKCE code challenge method")
    state: Optional[str] = Field(None, description="Optional state parameter")
    scope: Optional[str] = Field(None, description="Optional scope parameter")
    
    class Config:
        extra = "ignore"

def validate_scope(requested_scope: str | None, client: OAuthClientInformationFull) -> list[str] | None:
    if requested_scope is None:
        return None
    requested_scopes = requested_scope.split(" ")
    allowed_scopes = [] if client.scope is None else client.scope.split(" ")
    for scope in requested_scopes:
        if scope not in allowed_scopes:
            raise InvalidRequestError(f"Client was not registered with scope {scope}")
    return requested_scopes

def validate_redirect_uri(auth_request: AuthorizationRequest, client: OAuthClientInformationFull) -> AnyHttpUrl:
    if auth_request.redirect_uri is not None:
        # Validate redirect_uri against client's registered redirect URIs
        if auth_request.redirect_uri not in client.redirect_uris:
            raise InvalidRequestError(
                f"Redirect URI '{auth_request.redirect_uri}' not registered for client"
            )
        return auth_request.redirect_uri
    elif len(client.redirect_uris) == 1:
        return client.redirect_uris[0]
    else:
        raise InvalidRequestError("redirect_uri must be specified when client has multiple registered URIs")

def create_authorization_handler(provider: OAuthServerProvider) -> Callable:
    """
    Create a handler for the OAuth 2.0 Authorization endpoint.
    
    Corresponds to authorizationHandler in src/server/auth/handlers/authorize.ts

    """
    
    async def authorization_handler(request: Request) -> Response:
        """
        Handler for the OAuth 2.0 Authorization endpoint.
        """
        # Validate request parameters
        try:
            if request.method == "GET":
                # Convert query_params to dict for pydantic validation
                params = dict(request.query_params)
                auth_request = AuthorizationRequest.model_validate(params)
            else:
                # Parse form data for POST requests
                form_data = await request.form()
                params = dict(form_data)
                auth_request = AuthorizationRequest.model_validate(params)
        except ValidationError as e:
            raise InvalidRequestError(str(e))
        
        # Get client information
        try:
            client = await provider.clients_store.get_client(auth_request.client_id)
        except OAuthError as e:
            # TODO: proper error rendering
            raise InvalidClientError(str(e))
        
        if not client:
            raise InvalidClientError(f"Client ID '{auth_request.client_id}' not found")
        
 
        # do validation which is dependent on the client configuration
        redirect_uri = validate_redirect_uri(auth_request, client)
        scopes = validate_scope(auth_request.scope, client)
        
        auth_params = AuthorizationParams(
            state=auth_request.state,
            scopes=scopes,
            code_challenge=auth_request.code_challenge,
            redirect_uri=redirect_uri,
        )
        
        response = RedirectResponse(url="", status_code=302, headers={"Cache-Control": "no-store"})
            
        try:
            # Let the provider handle the authorization flow
            await provider.authorize(client, auth_params, response)
            
            return response
        except Exception as e:
            return RedirectResponse(
                url=create_error_redirect(redirect_uri, e, auth_request.state),
                status_code=302,
                headers={"Cache-Control": "no-store"},
                )
    
    return authorization_handler

def create_error_redirect(redirect_uri: AnyUrl, error: Exception, state: Optional[str]) -> str:
    parsed_uri = urlparse(str(redirect_uri))
    if isinstance(error, OAuthError):
        query_params = {
            "error": error.error_code,
            "error_description": str(error)
        }
    else:
        query_params = {
            "error": "internal_error",
            "error_description": "An unknown error occurred"
        }
    # TODO: should we add error_uri?
    # if error.error_uri:
    #     query_params["error_uri"] = str(error.error_uri)
    if state:
        query_params["state"] = state
    
    new_query = urlencode(query_params)
    if parsed_uri.query:
        new_query = f"{parsed_uri.query}&{new_query}"
    
    return urlunparse(parsed_uri._replace(query=new_query))