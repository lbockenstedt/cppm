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
    ):
        self.host = host or os.getenv("CPPM_HOST", "")
        self.user = user or os.getenv("CPPM_USER", "")
        self.password = password or os.getenv("CPPM_PASS", "")
        self.client_id = client_id or os.getenv("CPPM_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("CPPM_CLIENT_SECRET", "")

        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

        self.session = requests.Session()
        self.session.verify = False

        if not self.host:
            logger.warning("CPPM_HOST not set. Client will be inactive until configured.")

    def update_config(self, host: str, user: str = "", password: str = "",
                      client_id: str = "", client_secret: str = ""):
        self.host = host
        self.user = user
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        self._token = None
        self._token_expiry = 0.0
        self.session.auth = None  # clear any stale basic auth from previous attempts
        logger.info(f"CPPM client reconfigured for host: {host}")

    def _base_url(self) -> str:
        host = self.host.strip()
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return host.rstrip("/")

    def _try_oauth(self, body: dict) -> Optional[str]:
        """Attempt a single OAuth2 token request; return access_token or None.
        Retries on transient network errors (connection reset, timeout) with
        exponential backoff to handle intermittent network instability."""
        grant = body.get("grant_type")
        cid = body.get("client_id", "<none>")
        max_retries = 3
        base_delay = 1.0
        for attempt in range(max_retries):
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
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                    requests.exceptions.ChunkedEncodingError) as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.warning(f"OAuth {grant} (client_id={cid}) transient error (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {delay:.1f}s...")
                    time.sleep(delay)
                    continue
                logger.warning(f"OAuth {grant} (client_id={cid}) failed after {max_retries} attempts: {e}")
                return None
            except Exception as e:
                logger.warning(f"OAuth {grant} (client_id={cid}) exception: {e}")
                return None
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
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {method} {url}: {e}")
            return {"status": "ERROR", "message": str(e)}
        except ValueError:
            return {"status": "ERROR", "message": "Non-JSON response from CPPM"}

    def query(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        return self._request("GET", endpoint, params=params)
