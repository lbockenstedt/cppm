"""HTTP client for the Aruba ClearPass Policy Manager (CPPM) REST API.

Handles credential loading from the environment / a local .env file, OAuth2
token acquisition (with basic-auth fallback), TLS verification policy and
uniform error reporting so callers always receive a dictionary.
"""
# requests performs the HTTPS calls and keeps a cookie/TLS-aware session.
import requests
# os reads environment variables; time tracks OAuth token expiry.
import os
import time
# logging records auth and request problems for operators.
import logging
# Type hints only; they document the shapes of values passed around.
from typing import Any, Dict, Optional

def load_dotenv():
    """Load environment variables from a local .env file if present."""
    # A missing .env is fine: credentials can also come from real environment variables.
    if os.path.exists(".env"):
        # Read the file line by line.
        with open(".env") as f:
            for line in f:
                # Ignore surrounding whitespace, blank lines and comment lines.
                line = line.strip()
                if line and not line.startswith("#"):
                    # Only KEY=VALUE lines are settings; split on the first "=" only.
                    if "=" in line:
                        key, value = line.split("=", 1)
                        # Export the setting, stripping spaces and optional surrounding quotes.
                        os.environ[key.strip()] = value.strip().strip('"').strip("'")

# Load .env once at import time so every CPPMClient sees the same settings.
load_dotenv()
# One named logger so all CPPM client messages can be filtered together.
logger = logging.getLogger("CPPMClient")


# Strings that mean "off/false" when a boolean setting arrives as text.
_FALSEY_STR = {"0", "false", "no", "off", "none", "null", ""}


def _as_bool(value: Any) -> bool:
    """Coerce a config value to bool WITHOUT the ``bool("false") is True`` trap.

    The instance's ``verify_ssl`` reaches us over JSON/config and can arrive as a
    real bool OR as a string ("false", "0", …) — e.g. hand-edited config, an
    older UI that stored the select value as text, or a relay that stringified
    it. Plain ``bool("false")`` is truthy, which would silently re-enable TLS
    verification on a self-signed ClearPass and fail every call with
    CERTIFICATE_VERIFY_FAILED. Treat the usual falsey strings as False."""
    # Strings are compared against the known falsey spellings.
    if isinstance(value, str):
        return value.strip().lower() not in _FALSEY_STR
    # Real booleans, numbers and None follow normal Python truthiness.
    return bool(value)


def _env_verify_tls() -> bool:
    """Read LM_CPPM_VERIFY_TLS env var to determine default TLS verification mode."""
    # Verification defaults to ON ("true") so production is secure unless told otherwise.
    value = os.getenv("LM_CPPM_VERIFY_TLS", "true").strip().lower()
    # Explicitly disabled: warn loudly because this weakens security.
    if value in {"0", "false", "no", "off"}:
        logger.warning("CPPM TLS certificate verification disabled via LM_CPPM_VERIFY_TLS=%s. "
                       "Use only for trusted self-signed lab systems.", value)
        return False
    # Any other value keeps verification on.
    return True


class CPPMClient:
    """REST client for Aruba ClearPass Policy Manager.

    Auth priority: OAuth2 password grant (preferred) -> client_credentials -> basic auth fallback.
    """
    def __init__(
        self,
        host: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ):
        """Initialize the ClearPass REST client with endpoint credentials and TLS configuration."""
        # Each setting comes from the argument when given, else from the environment.
        self.host = host or os.getenv("CPPM_HOST", "")
        self.user = user or os.getenv("CPPM_USER", "")
        self.password = password or os.getenv("CPPM_PASS", "")
        self.client_id = client_id or os.getenv("CPPM_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("CPPM_CLIENT_SECRET", "")

        # Cached OAuth access token and the epoch time at which it expires.
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

        # One shared session reuses connections and carries the TLS verify setting.
        self.session = requests.Session()
        # Per-device verify_ssl (from the instance config) wins when given;
        # otherwise fall back to the process-wide LM_CPPM_VERIFY_TLS env var,
        # same default (secure) either way.
        self.session.verify = _env_verify_tls() if verify_ssl is None else _as_bool(verify_ssl)
        # Log the effective TLS mode so certificate problems are easy to diagnose.
        logger.info("CPPMClient init: host=%r session.verify=%r (verify_ssl arg=%r)",
                    self.host, self.session.verify, verify_ssl)

        # Without a host the client exists but cannot talk to anything yet.
        if not self.host:
            logger.warning("CPPM_HOST not set. Client will be inactive until configured.")

    def update_config(self, host: str, user: str = "", password: str = "",
                      client_id: str = "", client_secret: str = "",
                      verify_ssl: Optional[bool] = None):
        """Update host address, credentials, and SSL verification settings dynamically."""
        # Replace the connection details with the new values.
        self.host = host
        self.user = user
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        # Only change TLS mode when the caller specified one.
        if verify_ssl is not None:
            self.session.verify = _as_bool(verify_ssl)
        # Forget any token issued for the old host/credentials.
        self._token = None
        self._token_expiry = 0.0
        self.session.auth = None  # clear any stale basic auth from previous attempts
        # Record the reconfiguration for troubleshooting.
        logger.info(f"CPPM client reconfigured for host: {host} (verify_ssl={self.session.verify})")

    def _base_url(self) -> str:
        """Construct normalized base HTTPS URL for ClearPass API requests."""
        # Default to HTTPS when the host was given without a scheme.
        host = self.host.strip()
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        # Drop any trailing slash so endpoint paths join cleanly.
        return host.rstrip("/")

    def _try_oauth(self, body: dict) -> Optional[str]:
        """Attempt a single OAuth2 token request; return access_token or None."""
        # Remember grant type and client id for log messages.
        grant = body.get("grant_type")
        cid = body.get("client_id", "<none>")
        # Request a token; auth=None stops the session sending stale basic-auth credentials.
        try:
            resp = self.session.post(
                f"{self._base_url()}/api/oauth",
                json=body,
                auth=None,
                timeout=10,
            )
            # Rejected request: log the status and a short body excerpt, then give up on this grant.
            if not resp.ok:
                logger.warning(f"OAuth {grant} (client_id={cid}): HTTP {resp.status_code} — {resp.text[:200]}")
                return None
            # Decode the token response.
            data = resp.json()
            token = data.get("access_token")
            # Success: remember when the token expires (default one hour if not stated).
            if token:
                self._token_expiry = time.time() + data.get("expires_in", 3600)
                logger.info(f"OAuth token obtained via {grant} (client_id={cid})")
            # A 200 without a token is unexpected; log the payload for debugging.
            else:
                logger.warning(f"OAuth {grant} (client_id={cid}): no access_token in response: {data}")
            # Return the token (or None).
            return token
        # Network/TLS/JSON errors: log and treat as "this grant failed".
        except Exception as e:
            logger.warning(f"OAuth {grant} (client_id={cid}) exception: {e}")
            return None

    def _get_token(self) -> Optional[str]:
        """Retrieve valid OAuth2 bearer token from cache or request a new one."""
        # Reuse the cached token until 30 seconds before it expires.
        if self._token and time.time() < self._token_expiry - 30:
            return self._token

        # Build candidates in preference order.
        # password grant (user context) is preferred over client_credentials when
        # user credentials are available — it inherits the user's operator profile
        # rather than the API client's potentially restricted profile.
        candidates = []

        # Password grant: try the configured client id first, then ClearPass's built-in "ClearPass".
        if self.user and self.password:
            for cid in ([self.client_id] if self.client_id else []) + ["ClearPass"]:
                # Request body for the password grant with this client id.
                body: dict = {
                    "grant_type": "password",
                    "username": self.user,
                    "password": self.password,
                    "client_id": cid,
                }
                # Include the client secret when one is configured.
                if self.client_secret:
                    body["client_secret"] = self.client_secret
                candidates.append(body)
            # Last resort: no client_id at all
            candidates.append({"grant_type": "password", "username": self.user, "password": self.password})

        # Client-credentials grant when an API client id/secret pair is configured.
        if self.client_id and self.client_secret:
            candidates.append({
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            })

        # Try each candidate in order and keep the first token that works.
        for body in candidates:
            token = self._try_oauth(body)
            if token:
                self._token = token
                return token

        # Explain why no token could be obtained.
        if not candidates:
            logger.warning("No OAuth2 credentials available — cannot obtain token")
        else:
            logger.error("All OAuth2 attempts failed")
        # No token: the caller may fall back to basic auth.
        return None

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute an authenticated HTTP request against ClearPass REST API."""
        # Refuse to send requests until a host is configured.
        if not self.host:
            return {"status": "ERROR", "message": "CPPM host not configured"}

        # Full URL plus any extra headers the caller supplied.
        url = f"{self._base_url()}/{endpoint.lstrip('/')}"
        headers = kwargs.pop("headers", {})

        # Prefer a bearer token; otherwise fall back to HTTP basic auth if credentials exist.
        token = self._get_token()
        request_auth = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif self.user and self.password:
            request_auth = (self.user, self.password)

        # Send the request (15s timeout) and turn HTTP error codes into exceptions.
        try:
            response = self.session.request(method, url, headers=headers, auth=request_auth, timeout=15, **kwargs)
            response.raise_for_status()
            # Tolerate empty success bodies (e.g. 204 No Content on DELETE) so a
            # clean delete isn't misreported as a Non-JSON error.
            if not response.content:
                return {"status": "SUCCESS"}
            # Return the decoded JSON body.
            return response.json()
        except requests.exceptions.HTTPError as e:
            # ClearPass returns the *why* (validation failures, missing fields)
            # in the response body — e.g. a 422 names the offending attribute.
            # str(e) alone is just the status line, so surface the body too.
            # Capture up to 500 characters of the error body as diagnostic detail.
            detail = ""
            if e.response is not None:
                try:
                    detail = (e.response.text or "")[:500]
                # Reading the body failed; continue without detail.
                except Exception:
                    detail = ""
            # Log the status code and body, then report them to the caller.
            code = e.response.status_code if e.response is not None else None
            logger.error("HTTP error %s for %s %s: %s", code, method, url, detail or "<no body>")
            msg = str(e) if not detail else f"{e} | body: {detail}"
            return {"status": "ERROR", "message": msg, "code": code}
        except requests.exceptions.SSLError as e:
            # A TLS verification failure against a self-signed ClearPass is the
            # single most common CPPM misconfig. str(e) buries the cause in a
            # long urllib3 chain, and — critically — it does NOT say whether THIS
            # client is even verifying. Surface the effective verify state so the
            # operator can tell instantly whether verify_ssl=false actually
            # reached the spoke (verify=False here + still SSLError = a different
            # problem; verify=True = the "allow self-signed" toggle never landed,
            # so redeploy the hub or set LM_CPPM_VERIFY_TLS=false on the spoke).
            logger.error("SSL error for %s %s (session.verify=%r): %s",
                         method, url, self.session.verify, e)
            # Choose a hint that explains what the current verify state implies.
            hint = (" — this spoke is still VERIFYING TLS (session.verify=True): "
                    "the instance's 'allow untrusted / self-signed' setting has "
                    "not reached this spoke. Redeploy/restart the hub so it "
                    "pushes verify_ssl=false, or set LM_CPPM_VERIFY_TLS=false on "
                    "the spoke and restart it."
                    if self.session.verify else
                    " — TLS verification is already OFF on this spoke, so this is "
                    "a different transport error (host/port/network), not a cert "
                    "trust problem.")
            # Report the error with the hint and the verify state the client actually used.
            return {"status": "ERROR", "message": f"{e}{hint}",
                    "verify_ssl": bool(self.session.verify)}
        except requests.exceptions.RequestException as e:
            # Other transport failures (timeouts, refused connections): log and report.
            logger.error(f"Request failed for {method} {url}: {e}")
            return {"status": "ERROR", "message": str(e)}
        # The response body was not valid JSON.
        except ValueError:
            return {"status": "ERROR", "message": "Non-JSON response from CPPM"}

    def query(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Perform a GET query against ClearPass REST API with optional query parameters."""
        # Delegate to the shared request helper with GET and the query parameters.
        return self._request("GET", endpoint, params=params)
