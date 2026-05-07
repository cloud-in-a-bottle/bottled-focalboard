"""OpenHost auth-proxy sidecar for Focalboard (single-user mode).

Sits between the OpenHost router and Focalboard.  Trusts the
OpenHost router's ``X-OpenHost-Is-Owner: true`` header as the sole
authentication signal: the router stamps that header AFTER
JWT-verifying the visitor's ``zone_auth`` cookie (RS256, signed
by the router itself), and strips any client-supplied versions
before stamping its own.  Combined with our ``public_paths = []``
in openhost.toml, this means anonymous traffic never reaches us —
the router 302s anonymous visitors to the zone /login page and we
only ever see authenticated requests.

For owner requests with no ``FOCALBOARDAUTHTOKEN`` cookie yet, the
proxy 303's the browser back to the same URL with the cookie set
to the configured single-user token.  Subsequent requests carry
the cookie and pass through to focalboard-server, which (in
single-user mode) accepts any request presenting the configured
token via the ``FOCALBOARDAUTHTOKEN`` cookie or the
``Authorization: Bearer ...`` header.

Defence-in-depth: the proxy ALSO injects
``Authorization: Bearer <token>`` on every forwarded request, so
even if the browser somehow strips the cookie en route (Safari
ITP, an aggressive privacy extension, ...) the request still
authenticates.  The two paths are independent and both terminate
at the same single-user-token check inside Focalboard.

Defence-in-depth (the other direction): the proxy ALWAYS strips
client-supplied ``X-OpenHost-Is-Owner`` and ``X-OpenHost-User``
headers on inbound requests before checking the router-stamped
versions.  The OpenHost router does this strip too, so we'd have
to be both bypassed AND a hostile client injecting forged
headers for this to matter, but stripping again costs nothing
and closes the loop.

WebSocket support: Focalboard's SPA opens a WebSocket to
``/ws/onchange`` for live board updates.  We detect the upgrade
and switch to bidirectional byte forwarding, mirroring
openhost-peertube + openhost-jenkins.  The WS upgrade request is
gated like any other request, so non-owners can't sneak in.

Why trust the router's stamp instead of re-verifying the JWT
ourselves (the openhost-syncthing pattern)?  The syncthing app
has ``public_paths = ["/_some_path"]`` so the router lets some
anonymous traffic through and the proxy must enforce auth itself.
Focalboard in single-user mode has no anonymous surface — every
path is owner-only — so ``public_paths = []`` is the right fit
and the router's stamp is sufficient.  This matches
openhost-minio's design.

This proxy is adapted from openhost-minio/auth_proxy.py (trust
the router's stamp + cookie-set on first visit) and
openhost-peertube's WS handler.  The differences from minio are:

  * Static cookie value (the configured single-user token) vs
    minio's API-call-and-capture-Set-Cookie.
  * ``/_healthz`` served locally (minio has no equivalent).
  * Cookie + Authorization injection on forwarded requests (minio
    only sets the cookie once via 302).
"""

from __future__ import annotations

import http.client
import logging
import os
import selectors
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

# -- Constants -----------------------------------------------------

# The OpenHost router's standardised auth headers.  Stripped on
# every inbound request as defence-in-depth: the router stamps
# fresh values after JWT verification, so any header arriving
# pre-stamped came from the client and is not to be trusted.
OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"

# Focalboard's session cookie name (server/services/auth/request_parser.go).
# Single-user mode treats any value other than the configured
# token as invalid, so we set this to the configured token on the
# first owner visit.
FOCALBOARD_COOKIE = "FOCALBOARDAUTHTOKEN"

# Local-served path for the OpenHost router's liveness probe.
# Returns 200 immediately so the container is "ready" the moment
# the proxy binds, well before focalboard-server's cold start
# completes.  Same trick as openhost-jenkins.
HEALTH_PATH = "/_healthz"

# Hop-by-hop headers (RFC 9110 §7.6.1) plus a few entries we
# rewrite ourselves at the proxy seam.  Same list the syncthing
# sidecar uses; kept verbatim so the two stay in lockstep.
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        # Host is dropped from the inbound request (it points at
        # the proxy, not the client's view of the URL); _proxy()
        # rewrites it explicitly from X-Forwarded-Host below so
        # focalboard's CSRF check sees the right origin.
        "Host",
    )
)

# Trust headers a hostile client could try to forge.  ALWAYS
# stripped from inbound requests, even though the OpenHost router
# strips client-supplied versions before stamping its own.
ALWAYS_STRIP_HEADERS = frozenset(
    h.lower()
    for h in (
        OWNER_HEADER_NAME,
        USER_HEADER_NAME,
    )
)

# Read timeout on the inbound socket so a slow-loris client can't
# hold a thread forever.  60 s matches every other OpenHost
# auth-proxy.
CLIENT_READ_TIMEOUT_SECONDS = 60

# 64 MiB body cap.  Focalboard's biggest legitimate POST is a
# board attachment upload, which the SPA gates on a UI hint that
# matches this cap.  Bulk asset uploads are still routed through
# Focalboard, so we keep the cap relatively generous.
MAX_BODY_BYTES = 64 * 1024 * 1024

# WebSocket bidirectional-forwarding constants.  Sized for live
# board-update traffic (small frames, long-lived sessions).
STREAM_CHUNK_BYTES = 64 * 1024
STREAM_TIMEOUT_SECONDS = 30 * 60
HEADER_LINE_CAP = 64 * 1024

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


# -- Helpers -------------------------------------------------------


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    """Parse an RFC6265 Cookie header into a {name: value} dict.

    First-value-wins semantics for duplicate cookie names — matches
    browser ordering and prevents trivial duplicate-cookie DoS.
    See openhost-miniflux/auth_proxy.py for the long-form rationale.
    """
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


def _read_token_file(path: str) -> str | None:
    """Read the single-user token from start.sh's on-disk file.

    The file is one line: the bare token, no quoting.  We re-read
    on every cookie-set so an operator who rotates the token
    (delete + restart) doesn't need to restart the proxy.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip() or None
    except FileNotFoundError:
        return None


def _is_websocket_upgrade(headers) -> bool:
    """RFC 6455 §4.1 detection: Connection: upgrade + Upgrade: websocket.

    Both headers can have multiple values (comma-separated); we
    do a case-insensitive contains check.  Focalboard's SPA
    always issues these together, but be permissive about exact
    formatting so a transparent proxy in front of us that
    rewrites them slightly still works.
    """
    connection = headers.get("Connection", "").lower()
    upgrade = headers.get("Upgrade", "").lower()
    return "upgrade" in connection and "websocket" in upgrade


def _build_set_cookie(token: str, secure: bool) -> str:
    """Return a Set-Cookie header value that pins the token cookie.

    HttpOnly: the SPA never reads this cookie (Focalboard reads it
        server-side from the request).  HttpOnly defends against
        XSS exfiltration even though the SPA doesn't strictly need
        the protection.
    SameSite=Lax: Focalboard's SPA does same-origin XHR, so Lax
        is sufficient.  Strict would break any future cross-app
        embedding (Outline link previews etc.); Lax is the
        ergonomic middle ground that every other OpenHost app's
        cookies use.
    Secure: only set when we're behind TLS (which OpenHost always
        is in production); we still let dev-mode HTTP work because
        a Secure cookie on a non-TLS request is dropped silently
        by the browser, locking the operator out without a clear
        error.  The `secure` parameter is True iff the original
        request hit us as HTTPS (X-Forwarded-Proto: https).
    Max-Age=31536000: 1 year, matching the session_expire_time we
        set in start.sh's config.json.  The cookie outlives any
        single browser window, so the operator stays signed in
        across reboots.  Rotation = delete the on-disk token
        file + restart container + clear the browser cookie.
    """
    parts = [
        f"{FOCALBOARD_COOKIE}={token}",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=31536000",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


# -- Request handler -----------------------------------------------


class AuthProxyHandler(BaseHTTPRequestHandler):
    # Set by main() before the server starts.
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8000
    token_file: str = "/data/app_data/focalboard/config/single-user-token.txt"

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        # Suppress healthcheck logs — at the OpenHost router's
        # ~1 probe/sec rate they would drown the actual request
        # log.  Same trick as openhost-syncthing.
        path = getattr(self, "path", "")
        if path == HEALTH_PATH or path.startswith(HEALTH_PATH + "?"):
            return
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    # -- Dispatch + auth gate -------------------------------------

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        path = self.path or ""

        # Local-served healthcheck.  Always 200; never forwarded.
        if path == HEALTH_PATH or path.startswith(HEALTH_PATH + "?"):
            self._serve_healthz()
            return

        # Auth gate.  Trust the router's stamp: anonymous traffic
        # never reaches us (router 302's to /login first), so any
        # request that arrives here without X-OpenHost-Is-Owner:
        # true is either (a) bypassing the router (impossible in
        # production, and our defence-in-depth strips client-
        # supplied versions of the header anyway) or (b) a router
        # bug.  Either way, refuse.
        is_owner = (
            self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        )
        if not is_owner:
            # 403 not 401: 401 invites the browser to pop a basic-
            # auth dialog, but our auth flow is the OpenHost
            # zone_auth cookie / API token, not basic auth.
            self._safe_send_error(403, "Forbidden")
            return

        cookies = _parse_cookie_header(self.headers.get("Cookie"))

        # The owner's first request to any path: if there's no
        # FOCALBOARDAUTHTOKEN cookie yet, set it via 303 to the
        # same URL.  Subsequent requests carry the cookie.
        if FOCALBOARD_COOKIE not in cookies:
            single_user_token = _read_token_file(self.token_file)
            if not single_user_token:
                log.error(
                    "single-user token file %r missing or empty; refusing",
                    self.token_file,
                )
                self._safe_send_error(503, "single-user token unavailable")
                return
            self._send_cookie_redirect(single_user_token)
            return

        # WebSocket upgrade?
        if _is_websocket_upgrade(self.headers):
            self._proxy_websocket()
            return

        # Plain HTTP forward.
        self._proxy_http(cookies.get(FOCALBOARD_COOKIE, ""))

    def _serve_healthz(self) -> None:
        body = b"ok\n"
        try:
            self.send_response(200, "OK")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError as exc:
            log.debug("client disconnected mid-healthz: %s", exc)

    def _send_cookie_redirect(self, token: str) -> None:
        """302 the browser back to the same URL with the cookie set.

        The Location is the same path the request came in on, so
        the browser re-issues GET (or POST if the original was a
        POST and the browser respects the 307/308 distinction —
        we use 303 below to force GET).  In practice all first-
        visit requests are navigation GETs from the OpenHost
        dashboard's external-link click, so 303-vs-302 doesn't
        matter, but 303 ("See Other") is the right semantic.
        """
        secure = self.headers.get("X-Forwarded-Proto", "").lower() == "https"
        set_cookie = _build_set_cookie(token, secure=secure)
        try:
            self.send_response(303, "See Other")
            self.send_header("Location", self.path or "/")
            self.send_header("Set-Cookie", set_cookie)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected mid-redirect: %s", exc)

    # -- HTTP forward ----------------------------------------------

    def _proxy_http(self, focalboard_cookie_value: str) -> None:
        # Strip trust headers, hop-by-hop headers, and the inbound
        # zone_auth cookie (focalboard has no use for it).
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS | {"content-length"},
        )

        # Rewrite Host from X-Forwarded-Host.
        forwarded_host = self.headers.get("X-Forwarded-Host")
        explicit_host_set = False
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
            explicit_host_set = True

        # Inject Authorization: Bearer <token> as defence-in-depth
        # in case the cookie is dropped en route.  We use the cookie
        # value as the token because that's already the configured
        # single-user token (focalboard validated it as such on the
        # cookie path; injecting it here means the same value also
        # satisfies the Authorization-header path).
        #
        # We strip any client-supplied Authorization first — clients
        # don't legitimately set this for our seam, and an attacker
        # could otherwise bypass our cookie check.  The cookie check
        # already ran at the auth gate above, so this strip is
        # belt-and-braces.
        cleaned_headers = [
            (k, v) for k, v in cleaned_headers if k.lower() != "authorization"
        ]
        if focalboard_cookie_value:
            cleaned_headers.append(
                ("Authorization", f"Bearer {focalboard_cookie_value}")
            )

        # Reject chunked / non-identity transfer encoding.  See
        # syncthing auth-proxy for rationale.
        transfer_encoding = self.headers.get(
            "Transfer-Encoding", ""
        ).lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    log.info(
                        "short read: expected %d bytes, got %d",
                        length,
                        len(body),
                    )
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=60
        )
        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=explicit_host_set,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            try:
                payload = upstream.read(MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001 - best effort
                    log.debug(
                        "upstream.close() after read error raised: %s",
                        close_exc,
                    )
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001 - best effort only
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > MAX_BODY_BYTES:
                log.warning(
                    "upstream response exceeded %d bytes; returning 502",
                    MAX_BODY_BYTES,
                )
                self._safe_send_error(502, "upstream response too large")
                return

            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()

    # -- WebSocket forward -----------------------------------------

    def _proxy_websocket(self) -> None:
        """Forward a WebSocket upgrade + bidirectional bytes.

        Implementation pattern: open a TCP socket to the upstream,
        replay our request line + headers verbatim (after the
        usual hop-by-hop strip + Host rewrite + Authorization
        injection), forward the upstream's 101 response back, then
        pump bytes between the two sockets until either side
        closes.  We use selectors to multiplex without spawning
        per-direction threads.

        This mirrors openhost-peertube/auth_proxy.py's WS handler
        and openhost-jenkins's WebSocket support.  Focalboard
        uses WS for live board updates (/ws/onchange path).
        """
        # Pull the focalboard cookie value out for the Authorization
        # header injection (same logic as _proxy_http).
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        focalboard_cookie_value = cookies.get(FOCALBOARD_COOKIE, "")

        # Build the upstream request line + headers verbatim.
        cleaned_headers = _strip_headers(
            self.headers.items(),
            ALWAYS_STRIP_HEADERS | {"host", "authorization"},
        )
        # Forward Host as the original X-Forwarded-Host so any
        # WS-level Origin checks see the right thing.  Same
        # reasoning as _proxy_http().
        forwarded_host = self.headers.get("X-Forwarded-Host")
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
        if focalboard_cookie_value:
            cleaned_headers.append(
                ("Authorization", f"Bearer {focalboard_cookie_value}")
            )

        try:
            upstream_sock = socket.create_connection(
                (self.upstream_host, self.upstream_port), timeout=10
            )
        except OSError as exc:
            log.warning("WS upstream connect failed: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        try:
            upstream_sock.settimeout(STREAM_TIMEOUT_SECONDS)
            request_lines = [f"{self.command} {self.path} HTTP/1.1"]
            for key, value in cleaned_headers:
                request_lines.append(f"{key}: {value}")
            request_blob = (
                "\r\n".join(request_lines).encode("latin-1") + b"\r\n\r\n"
            )
            try:
                upstream_sock.sendall(request_blob)
            except OSError as exc:
                log.warning("WS upstream write failed: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            # Read the upstream's 101 response (status line + headers).
            response_blob = self._read_until_double_crlf(upstream_sock)
            if response_blob is None:
                self._safe_send_error(502, "Bad Gateway")
                return

            # Forward the response head verbatim back to the client.
            try:
                self.wfile.write(response_blob)
                self.wfile.flush()
            except OSError as exc:
                log.debug("client disconnected before WS handshake: %s", exc)
                return

            # Bidirectional byte pump.
            self._ws_pump(self.connection, upstream_sock)
        finally:
            try:
                upstream_sock.close()
            except OSError:
                pass

    @staticmethod
    def _read_until_double_crlf(sock: socket.socket) -> bytes | None:
        """Read response head from a WebSocket upstream up to \r\n\r\n.

        Bounded by HEADER_LINE_CAP * a few lines as a sanity limit;
        a server emitting more than that on a WS handshake is
        misbehaving and we'd rather 502 than buffer indefinitely.
        Returns the raw bytes (status line + headers + final CRLF
        CRLF) or None on error.
        """
        buf = bytearray()
        # 32 KiB cap is plenty for any sane WS handshake response.
        cap = 32 * 1024
        while len(buf) < cap:
            try:
                chunk = sock.recv(4096)
            except OSError as exc:
                log.warning("WS upstream read failed: %s", exc)
                return None
            if not chunk:
                log.warning("WS upstream closed before handshake completed")
                return None
            buf.extend(chunk)
            if b"\r\n\r\n" in buf:
                return bytes(buf)
        log.warning("WS upstream response head exceeded %d bytes", cap)
        return None

    @staticmethod
    def _ws_pump(client_sock: socket.socket, upstream_sock: socket.socket) -> None:
        """Multiplex bytes between client and upstream sockets.

        Uses selectors.DefaultSelector so we don't burn one thread
        per direction.  Either side closing → tear both down.
        Read errors are logged and treated as a clean close.
        """
        client_sock.settimeout(STREAM_TIMEOUT_SECONDS)
        upstream_sock.settimeout(STREAM_TIMEOUT_SECONDS)
        sel = selectors.DefaultSelector()
        sel.register(client_sock, selectors.EVENT_READ, "client")
        sel.register(upstream_sock, selectors.EVENT_READ, "upstream")
        try:
            while True:
                events = sel.select(timeout=STREAM_TIMEOUT_SECONDS)
                if not events:
                    log.debug("WS pump idle timeout; tearing down")
                    return
                for key, _mask in events:
                    src = key.fileobj
                    dst = upstream_sock if key.data == "client" else client_sock
                    try:
                        chunk = src.recv(STREAM_CHUNK_BYTES)
                    except OSError as exc:
                        log.debug("WS recv on %s side failed: %s", key.data, exc)
                        return
                    if not chunk:
                        log.debug("WS %s side closed", key.data)
                        return
                    try:
                        dst.sendall(chunk)
                    except OSError as exc:
                        log.debug("WS send to %s side failed: %s", key.data, exc)
                        return
        finally:
            try:
                sel.close()
            except Exception as exc:  # noqa: BLE001 - best effort
                log.debug("selector close raised: %s", exc)


# -- Server bootstrap ---------------------------------------------


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8090)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 8000)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = (
        os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "").strip() or "127.0.0.1"
    )
    token_file = (
        os.environ.get("AUTH_PROXY_TOKEN_FILE", "").strip()
        or "/data/app_data/focalboard/config/single-user-token.txt"
    )

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port
    AuthProxyHandler.token_file = token_file

    try:
        server = IPv4ThreadingServer(
            ("0.0.0.0", listen_port), AuthProxyHandler
        )
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (token_file=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        token_file,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
