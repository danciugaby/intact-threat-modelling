"""Bearer-token authentication against Keycloak (OIDC access tokens, verified locally
with the realm's JWKS). Replaces flask-oidc, which was never actually enforced: the old
decorator checked a config key ('Keycloak') that did not exist."""
import logging
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request

log = logging.getLogger(__name__)
_jwks_clients = {}


def _issuer(cfg):
    return f"{cfg['KEYCLOAK_SERVER_URL']}/realms/{cfg['KEYCLOAK_REALM']}"


def _jwks(cfg):
    iss = _issuer(cfg)
    if iss not in _jwks_clients:
        _jwks_clients[iss] = jwt.PyJWKClient(f"{iss}/protocol/openid-connect/certs", cache_keys=True,
                                             lifespan=3600)
    return _jwks_clients[iss]


def _roles(claims, client_id):
    roles = set((claims.get("realm_access") or {}).get("roles", []))
    if client_id:
        roles |= set(((claims.get("resource_access") or {}).get(client_id) or {}).get("roles", []))
    return roles


def verify_token(token, cfg):
    key = _jwks(cfg).get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256", "RS384", "RS512", "ES256", "PS256"],
                        issuer=_issuer(cfg), options={"verify_aud": False, "require": ["exp", "iss"]})
    client = cfg.get("KEYCLOAK_CLIENT_ID")
    if client:
        aud = claims.get("aud") or []
        aud = [aud] if isinstance(aud, str) else aud
        if client not in aud and claims.get("azp") != client:
            raise jwt.InvalidAudienceError("token not issued for this client")
    role = cfg.get("KEYCLOAK_REQUIRED_ROLE")
    if role and role not in _roles(claims, client):
        raise PermissionError(f"missing role '{role}'")
    return claims


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        cfg = current_app.config
        if not cfg.get("AUTH_ENABLED"):
            return f(*args, **kwargs)
        header = request.headers.get("Authorization", "")
        if not header.lower().startswith("bearer "):
            return jsonify({"error": "missing bearer token"}), 401
        try:
            g.user = verify_token(header.split(" ", 1)[1].strip(), cfg)
        except PermissionError as exc:
            return jsonify({"error": str(exc)}), 403
        except Exception as exc:  # any JWT / JWKS failure
            log.info("Rejected token: %s", exc)
            return jsonify({"error": "invalid token"}), 401
        return f(*args, **kwargs)

    return wrapper
