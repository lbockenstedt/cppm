import requests
import os
import time
import logging
from typing import Any, Dict, Optional

def load_dotenv():
    if os.path.exists(".env"):
        with open(".env") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        os.environ[key.strip()] = value.strip().strip('"').strip("'")

load_dotenv()
logger = logging.getLogger("CPPMClient")


_FALSEY_STR = {"0", "false", "no", "off", "none", "null", ""}


def _as_bool(value: Any) -> bool:
    """Coerce a config value to bool WITHOUT the ``bool("false") is True`` trap.

    The instance's ``verify_ssl`` reaches us over JSON/config and can arrive as a
    real bool OR as a string ("false", "0", …) — e.g. hand-edited config, an
    older UI that stored the select value as text, or a relay that stringified
    it. Plain ``bool("false")`` is truthy, which would silently re-enable TLS
    verification on a self-signed ClearPass and fail every call with
    CERTIFICATE_VERIFY_FAILED. Treat the usual falsey strings as False."""
    if isinstance(value, str):
        return value.strip().lower() not in _FALSEY_STR
    return bool(value)


def _env_verify_tls() -> bool:
    value = os.getenv("LM_CPPM_VERIFY_TLS", "true").strip().lower()
    if value in {"0", "false", "no", "off"}:
        logger.warning("CPPM TLS certificate verification disabled via LM_CPPM_VERIFY_TLS=%s. "
                       "Use only for trusted self-signed lab systems.", value)
        return False
    return True


class CPPMClient:
    """
    REST client for Aruba ClearPass Policy Manager.
    Auth priority: OAuth2 client_credentials (preferred) → basic auth fallback.
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
        self.host = host or os.getenv("CPPM_HOST", "")
        self.user = user or os.getenv("CPPM_USER", "")
        self.password = password or os.getenv("CPPM_PASS", "")
        self.client_id = client_id or os.getenv("CPPM_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("CPPM_CLIENT_SECRET", "")

        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

        self.session = requests.Session()
        # Per-device verify_ssl (from the instance config) wins when given;
        # otherwise fall back to the process-wide LM_CPPM_VERIFY_TLS env var,
        # same default (secure) either way.
        self.session.verify = _env_verify_tls() if verify_ssl is None else _as_bool(verify_ssl)
        logger.info("CPPMClient init: host=%r session.verify=%r (verify_ssl arg=%r)",
                    self.host, self.session.verify, verify_ssl)

        if not self.host:
            logger.warning("CPPM_HOST not set. Client will be inactive until configured.")

    def update_config(self, host: str, user: str = "", password: str = "",
                      client_id: str = "", client_secret: str = "",
                      verify_ssl: Optional[bool] = None):
        self.host = host
        self.user = user
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        if verify_ssl is not None:
            self.session.verify = _as_bool(verify_ssl)
        self._token = None
        self._token_expiry = 0.0
        self.session.auth = None  # clear any stale basic auth from previous attempts
        logger.info(f"CPPM client reconfigured for host: {host} (verify_ssl={self.session.verify})")

    def _base_url(self) -> str:
        host = self.host.strip()
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return host.rstrip("/")

    def _try_oauth(self, body: dict) -> Optional[str]:
        """Attempt a single OAuth2 token request; return access_token or None."""
        grant = body.get("grant_type")
        cid = body.get("client_id", "<none>")
        try:
            resp = self.session.post(
                f"{self._base_url()}/api/oauth",
                json=body,
                auth=None,
                timeout=10,
            )
            if not resp.ok:
                logger.warning(f"OAuth {grant} (client_id={cid}): HTTP {resp.status_code} — {resp.text[:200]}")
                return None
            data = resp.json()
            token = data.get("access_token")
            if token:
                self._token_expiry = time.time() + data.get("expires_in", 3600)
                logger.info(f"OAuth token obtained via {grant} (client_id={cid})")
            else:
                logger.warning(f"OAuth {grant} (client_id={cid}): no access_token in response: {data}")
            return token
        except Exception as e:
            logger.warning(f"OAuth {grant} (client_id={cid}) exception: {e}")
            return None

    def _get_token(self) -> Optional[str]:
        if self._token and time.time() < self._token_expiry - 30:
            return self._token

        # Build candidates in preference order.
        # password grant (user context) is preferred over client_credentials when
        # user credentials are available — it inherits the user's operator profile
        # rather than the API client's potentially restricted profile.
        candidates = []

        if self.user and self.password:
            for cid in ([self.client_id] if self.client_id else []) + ["ClearPass"]:
                body: dict = {
                    "grant_type": "password",
                    "username": self.user,
                    "password": self.password,
                    "client_id": cid,
                }
                if self.client_secret:
                    body["client_secret"] = self.client_secret
                candidates.append(body)
            # Last resort: no client_id at all
            candidates.append({"grant_type": "password", "username": self.user, "password": self.password})

        if self.client_id and self.client_secret:
            candidates.append({
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            })

        for body in candidates:
            token = self._try_oauth(body)
            if token:
                self._token = token
                return token

        if not candidates:
            logger.warning("No OAuth2 credentials available — cannot obtain token")
        else:
            logger.error("All OAuth2 attempts failed")
        return None

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        if not self.host:
            return {"status": "ERROR", "message": "CPPM host not configured"}

        url = f"{self._base_url()}/{endpoint.lstrip('/')}"
        headers = kwargs.pop("headers", {})

        token = self._get_token()
        request_auth = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif self.user and self.password:
            request_auth = (self.user, self.password)

        try:
            response = self.session.request(method, url, headers=headers, auth=request_auth, timeout=15, **kwargs)
            response.raise_for_status()
            # Tolerate empty success bodies (e.g. 204 No Content on DELETE) so a
            # clean delete isn't misreported as a Non-JSON error.
            if not response.content:
                return {"status": "SUCCESS"}
            return response.json()
        except requests.exceptions.HTTPError as e:
            # ClearPass returns the *why* (validation failures, missing fields)
            # in the response body — e.g. a 422 names the offending attribute.
            # str(e) alone is just the status line, so surface the body too.
            detail = ""
            if e.response is not None:
                try:
                    detail = (e.response.text or "")[:500]
                except Exception:
                    detail = ""
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
            hint = (" — this spoke is still VERIFYING TLS (session.verify=True): "
                    "the instance's 'allow untrusted / self-signed' setting has "
                    "not reached this spoke. Redeploy/restart the hub so it "
                    "pushes verify_ssl=false, or set LM_CPPM_VERIFY_TLS=false on "
                    "the spoke and restart it."
                    if self.session.verify else
                    " — TLS verification is already OFF on this spoke, so this is "
                    "a different transport error (host/port/network), not a cert "
                    "trust problem.")
            return {"status": "ERROR", "message": f"{e}{hint}",
                    "verify_ssl": bool(self.session.verify)}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {method} {url}: {e}")
            return {"status": "ERROR", "message": str(e)}
        except ValueError:
            return {"status": "ERROR", "message": "Non-JSON response from CPPM"}

    def query(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        return self._request("GET", endpoint, params=params)
