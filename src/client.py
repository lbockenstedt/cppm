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
from typing import Any, Dict, List, Optional

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


# ClearPass refuses a database write on a node whose database is read-only (a
# subscriber, or a node cut off from its publisher) with an error such as HTTP
# 500 "SQLSTATE[P0001]: Raise exception: 7 ERROR: Replication: Writes on t…".
# Issuing an OAuth token is such a write, so every token request fails and the
# API calls made without a token are then refused (403). Matched
# case-insensitively anywhere in the reply body.
_READ_ONLY_DB_TEXT = "replication: writes on"
# What the operator should do about it; added to the logs and error messages.
_READ_ONLY_DB_HINT = ("ClearPass refused a database write on this node, so it cannot issue an "
                      "OAuth token: the node is likely a subscriber, or cut off from its "
                      "publisher. Point LM at the cluster's publisher.")


def auth_failure_hint(text: Any) -> str:
    """Return what an operator should do about a failed OAuth reply body, or ""
    when the body names no cause we know. The only known cause is ClearPass's
    read-only database reply ("Replication: Writes on …", ``_READ_ONLY_DB_TEXT``)."""
    return _READ_ONLY_DB_HINT if _READ_ONLY_DB_TEXT in str(text or "").lower() else ""


def _https_base(host: str) -> str:
    """Normalized base HTTPS URL for ``host``.

    Always HTTPS: every request carries a bearer token, basic-auth credentials
    or an OAuth grant with the password or client secret, so a configured
    ``http://`` host is upgraded rather than sent in cleartext. ClearPass serves
    its REST API only over HTTPS.
    """
    # Default to HTTPS when the host was given without a scheme.
    host = (host or "").strip()
    if host.lower().startswith("http://"):
        logger.warning("CPPM host %r uses http://; using https:// so credentials are never sent in cleartext",
                       host)
        host = "https://" + host[len("http://"):]
    elif not host.lower().startswith("https://"):
        host = f"https://{host}"
    # Drop any trailing slash so endpoint paths join cleanly.
    return host.rstrip("/")


class _Conn:
    """One ClearPass configuration: the host, the credentials, and the Session
    and OAuth token that belong to them.

    update_config builds a new _Conn and swaps it in whole; nothing in a _Conn
    is changed to point at another appliance. A request takes the current
    _Conn once and uses only it, so a reconfiguration while the request is in
    flight can never pair one appliance's URL with another's token, password,
    grant body or TLS setting. Each _Conn has its own Session, so the TLS
    verify mode is never shared through a pooled connection either.
    """

    def __init__(self, host: str, user: str, password: str, client_id: str,
                 client_secret: str, verify: bool):
        """Hold one configuration; the token starts empty."""
        self.host = host
        self.user = user
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        # A Session per configuration reuses connections and carries the TLS verify setting.
        self.session = requests.Session()
        self.session.verify = verify
        # Cached OAuth access token for this configuration and when it expires (epoch).
        self.token: Optional[str] = None
        self.token_expiry: float = 0.0

    def identity(self) -> tuple:
        """The appliance and the whole login (every credential, so also which
        OAuth grant is used). Data read under one identity may differ from
        another's; TLS verify is left out because it changes how the
        appliance is reached, not what it returns."""
        return (self.host, self.user, self.password, self.client_id, self.client_secret)


def _conn_field(name: str) -> property:
    """A CPPMClient attribute that reads and writes the current _Conn's ``name``,
    so callers keep using ``client.host``, ``client.session`` and the rest."""
    return property(lambda self: getattr(self._conn, name),
                    lambda self, value: setattr(self._conn, name, value),
                    doc=f"The current configuration's {name}.")


class CPPMClient:
    """REST client for Aruba ClearPass Policy Manager.

    Auth priority: OAuth2 password grant (preferred) -> client_credentials -> basic auth fallback.
    The configuration lives in a _Conn that update_config replaces whole.
    """
    host = _conn_field("host")
    user = _conn_field("user")
    password = _conn_field("password")
    client_id = _conn_field("client_id")
    client_secret = _conn_field("client_secret")
    session = _conn_field("session")
    _token = _conn_field("token")
    _token_expiry = _conn_field("token_expiry")

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
        # Per-device verify_ssl (from the instance config) wins when given;
        # otherwise fall back to the process-wide LM_CPPM_VERIFY_TLS env var,
        # same default (secure) either way.
        self._conn = _Conn(
            host or os.getenv("CPPM_HOST", ""),
            user or os.getenv("CPPM_USER", ""),
            password or os.getenv("CPPM_PASS", ""),
            client_id or os.getenv("CPPM_CLIENT_ID", ""),
            client_secret or os.getenv("CPPM_CLIENT_SECRET", ""),
            _env_verify_tls() if verify_ssl is None else _as_bool(verify_ssl),
        )
        # Log the effective TLS mode so certificate problems are easy to diagnose.
        logger.info("CPPMClient init: host=%r session.verify=%r (verify_ssl arg=%r)",
                    self.host, self.session.verify, verify_ssl)

        # Without a host the client exists but cannot talk to anything yet.
        if not self.host:
            logger.warning("CPPM_HOST not set. Client will be inactive until configured.")

    def update_config(self, host: str, user: str = "", password: str = "",
                      client_id: str = "", client_secret: str = "",
                      verify_ssl: Optional[bool] = None):
        """Update host address, credentials, and SSL verification settings dynamically.

        Builds a new _Conn (new Session, no token) and swaps it in with one
        assignment. A request already in flight keeps the _Conn it took, so it
        finishes against the old appliance with the old appliance's own
        credentials and never sends the new ones there.
        """
        # TLS mode changes only when the caller specified one.
        verify = self._conn.session.verify if verify_ssl is None else _as_bool(verify_ssl)
        self._conn = _Conn(host, user, password, client_id, client_secret, verify)
        # Record the reconfiguration for troubleshooting.
        logger.info(f"CPPM client reconfigured for host: {host} (verify_ssl={verify})")

    @staticmethod
    def _drop_token(conn: _Conn, token: str) -> None:
        """Forget ``conn``'s cached token when it is still ``token``.

        Called when ClearPass refuses ``token`` with 401 (revoked, or expired
        before its stated expiry, e.g. after a ClearPass restart). Compared
        first so a newer token another thread has just fetched is kept.
        """
        if conn.token == token:
            conn.token = None
            conn.token_expiry = 0.0

    @staticmethod
    def _try_oauth(conn: _Conn, body: dict, hints: List[str]) -> Optional[str]:
        """Attempt a single OAuth2 token request to ``conn``'s host; return access_token or None.

        On success the expiry is recorded on ``conn``. A refusal whose reply
        names a known cause (auth_failure_hint) adds that hint to ``hints``,
        the list of the token run this request belongs to."""
        # Remember grant type and client id for log messages.
        grant = body.get("grant_type")
        cid = body.get("client_id", "<none>")
        # Request a token; auth=None stops the session sending stale basic-auth credentials.
        try:
            resp = conn.session.post(
                f"{_https_base(conn.host)}/api/oauth",
                json=body,
                auth=None,
                timeout=10,
            )
            # Rejected request: log the status, a short body excerpt and, when the body
            # names a known cause, what to do about it; then give up on this grant.
            if not resp.ok:
                hint = auth_failure_hint(resp.text)
                if hint and hint not in hints:
                    hints.append(hint)
                logger.warning(f"OAuth {grant} (client_id={cid}): HTTP {resp.status_code} — {resp.text[:200]}"
                               + (f" — {hint}" if hint else ""))
                return None
            # Decode the token response.
            data = resp.json()
            token = data.get("access_token")
            # Success: remember when the token expires (default one hour if not stated).
            if token:
                conn.token_expiry = time.time() + data.get("expires_in", 3600)
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

    @staticmethod
    def _grant_candidates(conn: _Conn) -> List[dict]:
        """The OAuth grant bodies ``conn``'s credentials allow, in the order the client tries them.

        The password grant (user context) is preferred over client_credentials
        when user credentials are available: it inherits the user's operator
        profile rather than the API client's potentially restricted profile.
        """
        candidates = []
        # Password grant: try the configured client id first, then ClearPass's built-in "ClearPass".
        if conn.user and conn.password:
            for cid in ([conn.client_id] if conn.client_id else []) + ["ClearPass"]:
                # Request body for the password grant with this client id.
                body: dict = {
                    "grant_type": "password",
                    "username": conn.user,
                    "password": conn.password,
                    "client_id": cid,
                }
                # Include the client secret when one is configured.
                if conn.client_secret:
                    body["client_secret"] = conn.client_secret
                candidates.append(body)
            # Last resort: no client_id at all
            candidates.append({"grant_type": "password", "username": conn.user, "password": conn.password})
        # Client-credentials grant when an API client id/secret pair is configured.
        if conn.client_id and conn.client_secret:
            candidates.append({
                "grant_type": "client_credentials",
                "client_id": conn.client_id,
                "client_secret": conn.client_secret,
            })
        return candidates

    def _get_token(self, hints: Optional[List[str]] = None,
                   conn: Optional[_Conn] = None) -> Optional[str]:
        """Retrieve a valid OAuth2 bearer token for ``conn`` (default: the
        current configuration) from its cache or request a new one.

        The token is fetched from, and cached on, ``conn`` only, so it is only
        ever sent to ``conn``'s host. When no token is obtained and a reply
        named a known cause, the hint is added to ``hints``; it stays empty
        otherwise. Each caller passes its own list rather than reading client
        state, so a token run on another thread can never add, or erase, the
        cause given for this call's failure."""
        conn = conn or self._conn
        # Reuse the cached token until 30 seconds before it expires.
        if conn.token and time.time() < conn.token_expiry - 30:
            return conn.token
        # Known causes this run's refusals named; private when the caller passed no list.
        hints = [] if hints is None else hints

        # Try each candidate in order and keep the first token that works.
        candidates = self._grant_candidates(conn)
        for body in candidates:
            token = self._try_oauth(conn, body, hints)
            if token:
                conn.token = token
                # A grant worked, so an earlier grant's failure explains nothing.
                hints.clear()
                return token

        # Explain why no token could be obtained, with what to do when a reply named the cause.
        if not candidates:
            logger.warning("No OAuth2 credentials available — cannot obtain token")
        else:
            logger.error("All OAuth2 attempts failed" + (f": {' '.join(hints)}" if hints else ""))
        # No token: the caller may fall back to basic auth.
        return None

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute an authenticated HTTP request against ClearPass REST API.

        Takes the current configuration (_Conn) once; the URL, credentials,
        token, 401 retry, Session and TLS diagnostics all come from it, so a
        reconfiguration mid-request never mixes two appliances."""
        conn = self._conn
        # Refuse to send requests until a host is configured.
        if not conn.host:
            return {"status": "ERROR", "message": "CPPM host not configured"}

        # Full URL plus any extra headers the caller supplied.
        url = f"{_https_base(conn.host)}/{endpoint.lstrip('/')}"
        headers = kwargs.pop("headers", {})

        # Prefer a bearer token; otherwise fall back to HTTP basic auth if credentials exist.
        # auth_hints gets the known cause, if any, of this request's own failed token run.
        auth_hints: List[str] = []
        token = self._get_token(auth_hints, conn)
        request_auth = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif conn.user and conn.password:
            request_auth = (conn.user, conn.password)

        # Send the request (15s timeout) and turn HTTP error codes into exceptions.
        try:
            response = conn.session.request(method, url, headers=headers, auth=request_auth, timeout=15, **kwargs)
            # A 401 on a bearer token means ClearPass no longer accepts that
            # token, though it has not reached the expiry we cached. Without
            # this, every call failed until the cached expiry (up to hours).
            # Drop it, fetch a new one and send once more; a second 401 is
            # reported as usual.
            if response.status_code == 401 and token:
                self._drop_token(conn, token)
                token = self._get_token(auth_hints, conn)
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                    response = conn.session.request(method, url, headers=headers, auth=None, timeout=15, **kwargs)
            response.raise_for_status()
            # Tolerate empty success bodies (e.g. 204 No Content on DELETE) so a
            # clean delete isn't misreported as a Non-JSON error. A GET always
            # answers with a JSON body, so an empty one (a proxy, a cut-off
            # reply) is a failure; as SUCCESS every reader took it for an empty
            # list or "not found", and a pager for the end of the list.
            if not response.content:
                if method.upper() == "GET":
                    return {"status": "ERROR",
                            "message": f"Empty response from CPPM (HTTP {response.status_code})"}
                return {"status": "SUCCESS"}
            # Return the decoded JSON body. Only the decode is in this try, so
            # a ValueError here is a bad body, never an InvalidURL or
            # MissingSchema from the send. Every requests release raises a
            # ValueError for one: its own JSONDecodeError from 2.27 (also a
            # RequestException, so the outer branch would take it first),
            # the json or simplejson one before that.
            try:
                return response.json()
            except ValueError:
                logger.error("Non-JSON response for %s %s", method, url)
                return {"status": "ERROR", "message": "Non-JSON response from CPPM"}
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
            # Sent without a token: when this request's failed token run named its
            # cause (a read-only ClearPass node), that explains this refusal, so
            # say it first. The transport errors below are unrelated, so they do not.
            if not token and auth_hints:
                msg = f"{' '.join(auth_hints)} {msg}"
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
                         method, url, conn.session.verify, e)
            # Choose a hint that explains what the current verify state implies.
            hint = (" — this spoke is still VERIFYING TLS (session.verify=True): "
                    "the instance's 'allow untrusted / self-signed' setting has "
                    "not reached this spoke. Redeploy/restart the hub so it "
                    "pushes verify_ssl=false, or set LM_CPPM_VERIFY_TLS=false on "
                    "the spoke and restart it."
                    if conn.session.verify else
                    " — TLS verification is already OFF on this spoke, so this is "
                    "a different transport error (host/port/network), not a cert "
                    "trust problem.")
            # Report the error with the hint and the verify state the client actually used.
            return {"status": "ERROR", "message": f"{e}{hint}",
                    "verify_ssl": bool(conn.session.verify)}
        except requests.exceptions.RequestException as e:
            # Other transport failures (timeouts, refused connections): log and report.
            logger.error(f"Request failed for {method} {url}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def query(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Perform a GET query against ClearPass REST API with optional query parameters."""
        # Delegate to the shared request helper with GET and the query parameters.
        return self._request("GET", endpoint, params=params)
