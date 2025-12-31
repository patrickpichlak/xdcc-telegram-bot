#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Integrations: xdcc.eu search + IRC XDCC/DCC download.

Public API:
    - search(query: str) -> list[SearchResult]
    - download(item: SearchResult, dest_dir: str) -> str

Payload contract (produced by search):
    payload = {
        'network': str,
        'server': str,    # e.g. irc.rizon.net
        'channel': str,   # e.g. #ELITEWAREZ
        'command': str,   # e.g. '[BOT]Nick xdcc send #78'
        'source_url': str
    }

Optional payload overrides for downloader:
    payload['nick']        (str)  IRC nick
    payload['realname']    (str)  IRC realname
    payload['port']        (int)  IRC port (default 6667)
    payload['ssl']         (bool) SSL (default False)
    payload['timeout_sec'] (int)  overall wait for DCC SEND (default 1800)
"""

from __future__ import annotations

import os
import re
import ssl
import time
import socket
import struct
import threading
import select
import random
from dataclasses import dataclass
from typing import Any, Optional, Tuple, List

__all__ = ["SearchResult", "search", "download"]

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from urllib.parse import quote_plus


# =========================
# Notifications helper
# =========================

def _notify(payload: dict[str, Any], msg: str) -> None:
    """Optional sync notification callback.

    Pass a callable in payload['notify'] that accepts a single str.
    The callable must be thread-safe and non-blocking (download() runs in a worker thread).
    """
    try:
        cb = payload.get("notify")
    except Exception:
        cb = None
    if callable(cb):
        try:
            cb(msg)
        except Exception:
            pass



# =========================
# Data model
# =========================

@dataclass(frozen=True)
class SearchResult:
    title: str
    size: str
    payload: dict[str, Any]


# =========================
# Scraper (xdcc.eu)
# =========================

INFO_A_TITLE = "Information on how to connect to server"

_HTTP_MIN_SECONDS_BETWEEN_REQUESTS = 2.0
_HTTP_CACHE_TTL_SEC = 180

_HTTP_throttle_lock = threading.Lock()
_HTTP_last_request_ts = 0.0

_HTTP_cache_lock = threading.Lock()
_HTTP_cache: dict[str, tuple[float, str]] = {}

# ---- FIX: define _HTTP_SESSION (was missing) ----
_HTTP_SESSION = requests.Session()
_HTTP_RETRY = Retry(
    total=4,
    connect=2,
    read=2,
    backoff_factor=0.8,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=("GET",),
    raise_on_status=False,
)
_HTTP_ADAPTER = HTTPAdapter(max_retries=_HTTP_RETRY, pool_connections=10, pool_maxsize=10)
_HTTP_SESSION.mount("https://", _HTTP_ADAPTER)
_HTTP_SESSION.mount("http://", _HTTP_ADAPTER)


def _HTTP_throttle() -> None:
    """Global throttling to avoid hammering remote services."""
    global _HTTP_last_request_ts
    with _HTTP_throttle_lock:
        now = time.time()
        wait = _HTTP_MIN_SECONDS_BETWEEN_REQUESTS - (now - _HTTP_last_request_ts)
        if wait > 0:
            # small jitter prevents accidental burst alignment
            time.sleep(wait + random.uniform(0.1, 0.4))
        _HTTP_last_request_ts = time.time()


def _HTTP_CACHE_get(url: str) -> Optional[str]:
    """Return cached HTML for URL if present and not expired."""
    now = time.time()
    with _HTTP_cache_lock:
        entry = _HTTP_cache.get(url)
        if not entry:
            return None
        exp_ts, html = entry
        if exp_ts < now:
            _HTTP_cache.pop(url, None)
            return None
        return html


def _HTTP_CACHE_set(url: str, html: str) -> None:
    """Store HTML response in cache with TTL."""
    with _HTTP_cache_lock:
        _HTTP_cache[url] = (time.time() + _HTTP_CACHE_TTL_SEC, html)


def _to_get_query(s: str) -> str:
    return quote_plus((s or "").strip())


def _fetch_html(url: str) -> str:
    """
    Polite HTML fetcher:
    - global throttling (min interval between requests)
    - in-memory cache (TTL)
    - retry/backoff on 429/5xx
    """
    cached = _HTTP_CACHE_get(url)
    if cached is not None:
        return cached

    _HTTP_throttle()

    headers = {
        # Be honest about the client.
        "User-Agent": "xdcc-telegram-bot/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "pl-PL,pl;q=0.9,en;q=0.8",
        "Connection": "keep-alive",
    }

    try:
        r = _HTTP_SESSION.get(url, headers=headers, timeout=30)
    except requests.RequestException as e:
        raise RuntimeError(f"Network/DNS error fetching {url}: {e}") from e

    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code} fetching {url}")

    r.encoding = r.encoding or "utf-8"

    html = r.text
    _HTTP_CACHE_set(url, html)
    return html


def _normalize_header(txt: str) -> str:
    return " ".join(txt.split()).strip().lower()


def _pick_cell_text(td) -> str:
    return td.get_text(" ", strip=True)


def search(query: str) -> list[SearchResult]:
    """Scrape xdcc.eu search results table and return SearchResult list."""
    source_url = f"https://xdcc.eu/search.php?searchkey={_to_get_query(query)}"
    html = _fetch_html(source_url)

    # lxml is faster, but fall back if not installed
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    table = soup.select_one("table#table")
    if not table:
        return []

    header_cells = table.select("thead th")
    headers = [_normalize_header(th.get_text(" ", strip=True)) for th in header_cells]
    header_to_idx = {h: i for i, h in enumerate(headers)}

    def idx_of(col_name: str) -> Optional[int]:
        return header_to_idx.get(_normalize_header(col_name))

    idx_network = idx_of("Network")
    idx_size = idx_of("Size")
    idx_name = idx_of("Name")
    if idx_network is None or idx_size is None or idx_name is None:
        return []

    results: list[SearchResult] = []
    for tr in table.select("tbody tr"):
        tds = tr.find_all("td", recursive=False)
        if len(tds) <= max(idx_network, idx_size, idx_name):
            continue

        network = _pick_cell_text(tds[idx_network])
        size = _pick_cell_text(tds[idx_size])
        name = _pick_cell_text(tds[idx_name])

        info_a = tr.find("a", attrs={"title": INFO_A_TITLE})
        command = server = channel = ""
        if info_a:
            command = info_a.get("data-p", "") or ""
            server = info_a.get("data-s", "") or ""
            channel = info_a.get("data-c", "") or ""

        results.append(
            SearchResult(
                title=name,
                size=size,
                payload={
                    "network": network,
                    "server": server,
                    "channel": channel,
                    "command": command,
                    "source_url": source_url,
                },
            )
        )
    return results


# =========================
# IRC/DCC helpers
# =========================

CTCP_DELIM = "\x01"


def _make_ctcp(msg: str) -> str:
    return f"{CTCP_DELIM}{msg}{CTCP_DELIM}"


def _parse_ctcp(trailing: str) -> Optional[str]:
    if trailing and trailing.startswith(CTCP_DELIM) and trailing.endswith(CTCP_DELIM) and len(trailing) >= 2:
        return trailing[1:-1]
    return None


def _dcc_tokenize(s: str) -> List[str]:
    out, cur, in_q = [], [], False
    for ch in s:
        if ch == '"':
            in_q = not in_q
            continue
        if ch.isspace() and not in_q:
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def _decode_dcc_ip(ip_field: str) -> str:
    if re.fullmatch(r"\d+", ip_field):
        n = int(ip_field)
        return socket.inet_ntoa(struct.pack("!I", n))
    return ip_field


def _safe_filename(name: str) -> str:
    name = name.replace("\\", "_").replace("/", "_").strip()
    return name or "download.bin"


@dataclass
class _DccSendOffer:
    sender_nick: str
    filename: str
    ip: str
    port: int
    size: Optional[int] = None
    token: Optional[str] = None


def _parse_dcc_message(ctcp_payload: str) -> Tuple[str, List[str]]:
    parts = _dcc_tokenize(ctcp_payload)
    if len(parts) < 2 or parts[0].upper() != "DCC":
        raise ValueError("Not DCC")
    return parts[1].upper(), parts[2:]


def _parse_dcc_send(sender_nick: str, ctcp_payload: str) -> _DccSendOffer:
    sub, args = _parse_dcc_message(ctcp_payload)
    if sub != "SEND":
        raise ValueError("Not SEND")
    if len(args) < 3:
        raise ValueError("Too few SEND args")

    filename = args[0]
    ip = _decode_dcc_ip(args[1])
    port = int(args[2])

    size: Optional[int] = None
    token: Optional[str] = None
    if len(args) >= 4 and re.fullmatch(r"\d+", args[3] or ""):
        size = int(args[3])
        if len(args) >= 5:
            token = args[4]
    elif len(args) >= 4:
        token = args[3]
    return _DccSendOffer(sender_nick=sender_nick, filename=filename, ip=ip, port=port, size=size, token=token)


def _build_dcc_resume(filename: str, port: int, position: int, token: Optional[str] = None) -> str:
    base = f'DCC RESUME "{filename}" {port} {position}'
    if token:
        base += f" {token}"
    return _make_ctcp(base)


def _dcc_receive_file(
    offer: _DccSendOffer,
    dest_dir: str,
    start_pos: int = 0,
    ack_every: int = 64 * 1024,
    timeout: int = 30,
    progress_cb=None,
) -> str:
    if offer.port == 0:
        raise RuntimeError("Reverse/passive DCC (port=0) not supported")
    os.makedirs(dest_dir, exist_ok=True)
    out_path = os.path.join(dest_dir, _safe_filename(offer.filename))
    mode = "ab" if start_pos > 0 else "wb"

    total = start_pos
    last_ack = start_pos

    with socket.create_connection((offer.ip, offer.port), timeout=timeout) as s:
        s.settimeout(timeout)
        with open(out_path, mode) as f:
            if start_pos:
                f.seek(0, os.SEEK_END)
            while True:
                chunk = s.recv(64 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                total += len(chunk)

                if callable(progress_cb):
                    try:
                        progress_cb(total, offer.size)
                    except Exception:
                        pass
                if (total - last_ack) >= ack_every or (offer.size is not None and total >= offer.size):
                    s.sendall(struct.pack("!I", total & 0xFFFFFFFF))
                    last_ack = total
                if offer.size is not None and total >= offer.size:
                    break
    return out_path


# ================
# IRC parsing
# ================

_IRC_MSG_RE = re.compile(r"^(?::(?P<prefix>\S+)\s+)?(?P<command>\S+)(?:\s+(?P<params>.+))?$")


def _split_irc_params(params: str) -> Tuple[List[str], str]:
    if not params:
        return [], ""
    if " :" in params:
        mid, trailing = params.split(" :", 1)
        return (mid.split() if mid else []), trailing
    return params.split(), ""


def _parse_prefix(prefix: str) -> Tuple[str, str, str]:
    nick = user = host = ""
    if not prefix:
        return nick, user, host
    if "!" in prefix:
        nick, rest = prefix.split("!", 1)
        if "@" in rest:
            user, host = rest.split("@", 1)
        else:
            user = rest
    else:
        nick = prefix
    return nick, user, host


def _parse_xdcc_data_p(data_p: str) -> Tuple[str, str]:
    tokens = data_p.strip().split()
    if len(tokens) < 2:
        raise ValueError("Bad data-p")
    bot = tokens[0]
    cmd = " ".join(tokens[1:])
    return bot, cmd


# =========================
# Download session
# =========================

class _IrcSession:
    def __init__(self, server: str, port: int, use_ssl: bool, nick: str, realname: str, channel: str):
        self.server = server
        self.port = port
        self.use_ssl = use_ssl
        self.nick = nick
        self.realname = realname
        self.channel = channel

        self.sock: Optional[socket.socket] = None
        self.recv_buf = b""
        self.send_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.last_pong = time.time()

        self.welcome_event = threading.Event()
        self.join_event = threading.Event()

        self.offer_event = threading.Event()
        self.offer: Optional[_DccSendOffer] = None
        self.offer_sender: Optional[str] = None

        self.queue_info: Optional[str] = None
        self._queue_notified = False

        self.accept_event = threading.Event()  # for RESUME/ACCEPT
        self.accepted = False

        self._thread: Optional[threading.Thread] = None

    def connect(self):
        raw = socket.create_connection((self.server, self.port), timeout=30)
        try:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass
        if self.use_ssl:
            ctx = ssl.create_default_context()
            raw = ctx.wrap_socket(raw, server_hostname=self.server)
        raw.setblocking(False)
        self.sock = raw

        self.send_raw(f"NICK {self.nick}")
        self.send_raw(f"USER {self.nick} 0 * :{self.realname}")

        self._thread = threading.Thread(target=self._run, daemon=False)
        self._thread.start()

    # ---- FIX: send_raw referenced undefined variable 's' ----
    def send_raw(self, line: str):
        s = self.sock
        if not s:
            return
        data = (line + "\r\n").encode("utf-8", errors="ignore")
        with self.send_lock:
            try:
                s.sendall(data)
            except OSError:
                # socket likely closed; ignore
                return

    def privmsg(self, target: str, msg: str):
        self.send_raw(f"PRIVMSG {target} :{msg}")

    def join(self, channel: str):
        self.send_raw(f"JOIN {channel}")

    def shutdown(self):
        """
        Graceful shutdown:
        - signal stop_event so _run loop exits
        - close socket safely
        - join thread (unless called from the same thread)
        """
        if self.stop_event.is_set():
            return
        self.stop_event.set()

        # Detach socket reference first to reduce races with select()/recv()
        s = self.sock
        self.sock = None

        try:
            # Best-effort QUIT (do not call send_raw here because self.sock is None)
            if s:
                try:
                    s.sendall(b"QUIT :bye\r\n")
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
        finally:
            t = self._thread
            if t and t.is_alive() and threading.current_thread() is not t:
                t.join(timeout=2.0)

    def _run(self):
        while not self.stop_event.is_set():
            s = self.sock
            if not s:
                break

            # ping watchdog
            if time.time() - self.last_pong > 300:
                self.shutdown()
                break

            try:
                r, _, _ = select.select([s], [], [], 1.0)
            except OSError as e:
                if getattr(e, "errno", None) == 9:  # EBADF
                    break
                raise

            if not r:
                continue

            try:
                data = s.recv(4096)
                if not data:
                    self.shutdown()
                    break
                self.recv_buf += data
            except BlockingIOError:
                continue
            except Exception:
                self.shutdown()
                break

            while b"\n" in self.recv_buf:
                raw_line, self.recv_buf = self.recv_buf.split(b"\n", 1)
                raw_line = raw_line.rstrip(b"\r")
                line = raw_line.decode("utf-8", errors="ignore")
                if line:
                    self._handle_line(line)

    def _handle_line(self, line: str):
        m = _IRC_MSG_RE.match(line)
        if not m:
            return
        prefix = m.group("prefix") or ""
        cmd = (m.group("command") or "").upper()
        params = m.group("params") or ""

        middle, trailing = _split_irc_params(params)
        nick, _, _ = _parse_prefix(prefix)

        if cmd == "PING":
            token = trailing if trailing else (middle[0] if middle else "")
            if token.startswith(":"):
                self.send_raw(f"PONG {token}")
            else:
                self.send_raw(f"PONG :{token}")
            return

        if cmd == "PONG":
            self.last_pong = time.time()
            return

        if cmd == "001":
            self.welcome_event.set()
            if self.channel:
                self.join(self.channel)
            return

        if cmd == "JOIN":
            joined = trailing or (middle[0] if middle else "")
            if nick.lower() == self.nick.lower() and joined.lower() == self.channel.lower():
                self.join_event.set()
            return

        if cmd in ("PRIVMSG", "NOTICE"):
            if not middle:
                return
            target = middle[0]
            trailing = trailing or ""

            # Queue / status notices (best effort). Example:
            # "** All Slots Full, Added you to the main queue ... in position 3."
            if cmd == "NOTICE" and target.lower() == self.nick.lower():
                msg = trailing
                if (("queue" in msg.lower()) or ("slots full" in msg.lower())) and not self._queue_notified:
                    mpos = re.search(r"position\s+(\d+)", msg, flags=re.IGNORECASE)
                    if mpos:
                        self.queue_info = f"Queue position {mpos.group(1)}"
                    else:
                        self.queue_info = "In queue"
                    self._queue_notified = True

            ctcp = _parse_ctcp(trailing)
            if ctcp and ctcp.upper().startswith("DCC "):
                try:
                    sub, _args = _parse_dcc_message(ctcp)
                except Exception:
                    return
                if sub == "SEND":
                    try:
                        offer = _parse_dcc_send(nick, ctcp)
                    except Exception:
                        return
                    self.offer = offer
                    self.offer_sender = nick
                    self.offer_event.set()
                elif sub == "ACCEPT":
                    self.accepted = True
                    self.accept_event.set()
            return


# =========================
# Public download()
# =========================

def download(item: SearchResult, dest_dir: str) -> str:
    """Download selected SearchResult into dest_dir and return final path."""
    payload = dict(item.payload or {})
    server = str(payload.get("server") or "").strip()
    channel = str(payload.get("channel") or "").strip()
    command = str(payload.get("command") or "").strip()

    if not server or not channel or not command:
        raise ValueError("SearchResult.payload must include server/channel/command")

    port = int(payload.get("port") or 6667)
    use_ssl = bool(payload.get("ssl") or False)

    nick = str(payload.get("nick") or "dcc_client")
    realname = str(payload.get("realname") or "Python DCC client")
    timeout_sec = int(payload.get("timeout_sec") or 1800)

    bot, xdcc_cmd = _parse_xdcc_data_p(command)

    sess = _IrcSession(server=server, port=port, use_ssl=use_ssl, nick=nick, realname=realname, channel=channel)
    _notify(payload, f"ℹ️[BOT] Łączenie z IRC {server}:{port} (SSL={use_ssl}) \nUSER: {nick}...")
    sess.connect()

    _notify(payload, "ℹ️[BOT] Połączono. Czekam na powitanie...")
    if not sess.welcome_event.wait(timeout=30):
        sess.shutdown()
        raise TimeoutError("⚠️[BOT] Nie udało się połączyć w ciągu 30s")

    # some networks don't echo JOIN to you; don't hard-fail
    sess.join_event.wait(timeout=15)
    _notify(payload, f"⚠️[BOT] Dołączono do kanału: {channel} ➡️Wysyłam request do: {bot}...")

    sess.privmsg(bot, xdcc_cmd)
    _notify(payload, f"ℹ️[BOT] Wysłano wiadomość: {xdcc_cmd}")

    deadline = time.time() + timeout_sec
    queue_reported = False
    while not sess.offer_event.is_set():
        remaining = max(0.0, deadline - time.time())
        if remaining <= 0:
            sess.shutdown()
            raise TimeoutError(f"Timeout waiting for DCC SEND (>{timeout_sec}s). Bot may keep you in queue.")
        sess.offer_event.wait(timeout=min(2.0, remaining))
        if sess.queue_info and not queue_reported:
            _notify(payload, f"ℹ️Jesteś w kolejce: {sess.queue_info}. Czekam na wolne miejsce...")
            queue_reported = True

    _notify(payload, "ℹ️Wysyłka otrzymana. Rozpoczynam transfer...")

    offer = sess.offer
    if not offer:
        sess.shutdown()
        raise RuntimeError("⚠️ DCC offer missing")

    if offer.port == 0:
        sess.shutdown()
        raise RuntimeError("⚠️ Reverse/passive DCC (port=0) not supported")

    os.makedirs(dest_dir, exist_ok=True)
    out_path = os.path.join(dest_dir, _safe_filename(offer.filename))
    start_pos = os.path.getsize(out_path) if os.path.exists(out_path) else 0

    # Progress notifications: only if size is known and >= 900MB, report every 10%
    big_threshold = 900 * 1024 * 1024
    progress_step = 10
    last_bucket = -1

    def progress_cb(done_bytes: int, total_bytes: Optional[int]):
        nonlocal last_bucket
        if not total_bytes or total_bytes < big_threshold:
            return
        pct = int((done_bytes * 100) / total_bytes)
        bucket = (pct // progress_step) * progress_step
        if bucket != last_bucket and bucket % progress_step == 0:
            if bucket >= 10 and bucket <= 100:
                _notify(payload, f"ℹ️Pobieram: {bucket}%")
            last_bucket = bucket


    if start_pos > 0 and (offer.size is None or start_pos < offer.size):
        resume_ctcp = _build_dcc_resume(offer.filename, offer.port, start_pos, offer.token)
        sess.privmsg(bot, resume_ctcp)
        sess.accept_event.wait(timeout=10)

    try:
        _notify(payload, f"☑️Rozpoczynam pobieranie: {offer.filename} ({offer.size if offer.size is not None else 'nieznany rozmiar'})")
        path = _dcc_receive_file(offer, dest_dir, start_pos=start_pos, progress_cb=progress_cb)
        # _notify(payload, f"✅Zakończono pobieranie do pliku: {path}")
    finally:
        sess.shutdown()

    return path


if __name__ == "__main__":
    import sys
    q = sys.argv[1] if len(sys.argv) >= 2 else "the osbournes s01e0"
    idx = int(sys.argv[2]) if len(sys.argv) >= 3 else 1
    dest = sys.argv[3] if len(sys.argv) >= 4 else "./downloads"

    results = search(q)
    if not results:
        print("⚠️ Brak wyników")
        raise SystemExit(1)
    item = results[idx - 1]
    print(f"Selected: {idx}. {item.title} ({item.size})")
    p = download(item, dest)
    print("Downloaded to:", p)
