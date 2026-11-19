"""
Quick Ping HUD
==============
A tiny always-on-top network monitor: ping to several hosts, live speed,
session totals, packet loss, public IP + location.

Requirements:
    pip install psutil            (required)
    pip install pillow            (optional, only for the bg.jpg background)

Build a single exe (no console window):
    pip install pyinstaller
    pyinstaller --noconsole --onefile --add-data "bg.jpg;." quick_ping_hud.py
    (drop --add-data if you don't use a background image)
"""

import copy
import ctypes
import errno
import json
import os
import platform
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
import urllib.request
from collections import deque
from tkinter import messagebox, ttk

import psutil

try:
    from PIL import Image, ImageTk
except ImportError:  # background image is optional
    Image = ImageTk = None

# ==================== CONFIG / DEFAULTS ====================

APP_NAME = "QuickPingHUD"
IS_WIN = platform.system() == "Windows"

DEFAULT_CONFIG = {
    "targets": [
        {"name": "8.8.8.8", "host": "8.8.8.8", "method": "icmp"},
        {"name": "4.2.2.4", "host": "4.2.2.4", "method": "icmp"},
        {"name": "Game", "host": "74.125.32.68", "method": "icmp"},
        {"name": "Google", "host": "google.com", "method": "icmp"},
        {"name": "Iran", "host": "gerdoo.me", "method": "icmp"},
    ],
    "loss_index": 2,      # which target feeds the packet-loss readout
    "interval": 1.0,      # seconds between pings
    "topmost": True,
}

METHODS = ("icmp", "tcp", "udp")
INTERVALS = (0.5, 1.0, 2.0, 3.0, 5.0)
MAX_TARGETS = 8
NAME_MAX = 14
PACKET_LOSS_WINDOW = 20
TIMEOUT = 1.0  # seconds, per probe

# Adapters to ignore when auto-picking the "real" interface for speed stats.
VIRTUAL_SUBSTR = ("loopback", "vpn", "virtual", "vmware", "vbox", "docker",
                  "wsl", "hyper-v", "npcap", "bluetooth", "isatap",
                  "teredo", "pseudo", "tap-", "tunnel")
VIRTUAL_PREFIX = ("tun", "tap", "utun", "veth", "br-", "docker", "lo0")

BG = "#121212"
FONT = "Consolas"

# ==================== PATHS / CONFIG FILE ====================


def resource_path(rel):
    base = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base, rel)


def config_path():
    base = (os.environ.get("APPDATA") if IS_WIN else None) or \
        os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, APP_NAME, "config.json")


def sanitize_config(raw):
    """Merge a loaded config with defaults, dropping anything invalid."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if not isinstance(raw, dict):
        return cfg
    try:
        targets = []
        for t in raw.get("targets", [])[:MAX_TARGETS]:
            host = str(t.get("host", "")).strip()
            if not host:
                continue
            method = t.get("method", "icmp")
            targets.append({
                "name": (str(t.get("name", "")).strip() or host)[:NAME_MAX],
                "host": host,
                "method": method if method in METHODS else "icmp",
            })
        if targets:
            cfg["targets"] = targets
            cfg["loss_index"] = int(raw.get("loss_index", 0))
        interval = float(raw.get("interval", 1.0))
        cfg["interval"] = interval if interval in INTERVALS else 1.0
        cfg["topmost"] = bool(raw.get("topmost", True))
    except Exception:
        return copy.deepcopy(DEFAULT_CONFIG)
    if not 0 <= cfg["loss_index"] < len(cfg["targets"]):
        cfg["loss_index"] = 0
    return cfg


def load_config():
    try:
        with open(config_path(), "r", encoding="utf-8") as f:
            return sanitize_config(json.load(f))
    except Exception:
        return copy.deepcopy(DEFAULT_CONFIG)


def save_config(cfg):
    try:
        path = config_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return None
    except Exception as e:
        return str(e)


# ==================== RUN AT STARTUP (Windows) ====================

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def startup_command():
    if getattr(sys, "frozen", False):  # PyInstaller exe
        return f'"{sys.executable}"'
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")  # no console
    if os.path.exists(pyw):
        exe = pyw
    return f'"{exe}" "{os.path.abspath(__file__)}"'


def is_startup_enabled():
    if not IS_WIN:
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.QueryValueEx(k, APP_NAME)
            return True
    except OSError:
        return False


def set_startup(enabled):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                        winreg.KEY_SET_VALUE) as k:
        if enabled:  # always rewrite so a moved exe gets fixed
            winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ,
                              startup_command())
        else:
            try:
                winreg.DeleteValue(k, APP_NAME)
            except FileNotFoundError:
                pass


# ==================== PING BACKENDS ====================
# Each pinger lives in its own worker thread and returns the round-trip
# time in milliseconds (float) or None on failure. No subprocesses are
# spawned (except the non-Windows ICMP fallback).


def split_host(host, default_port):
    host = host.strip()
    if host.count(":") == 1:
        h, p = host.rsplit(":", 1)
        if p.isdigit():
            return h, int(p)
    return host, default_port


class BasePinger:
    def __init__(self, host, default_port=None):
        self.host, self.port = split_host(host, default_port)
        self.literal = bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", self.host))
        self.ip = self.host if self.literal else None

    def resolve(self):
        if self.ip is None:
            try:
                self.ip = socket.gethostbyname(self.host)
            except OSError:
                return None
        return self.ip

    def fail(self):
        if not self.literal:  # re-resolve next time in case DNS changed
            self.ip = None

    def ping(self):
        raise NotImplementedError

    def close(self):
        pass


class IcmpEchoReply(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_ulong), ("Status", ctypes.c_ulong),
        ("RoundTripTime", ctypes.c_ulong), ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
        ("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


if IS_WIN:
    _icmp = ctypes.WinDLL("iphlpapi.dll")
    _icmp.IcmpCreateFile.restype = ctypes.c_void_p
    _icmp.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    _icmp.IcmpSendEcho.argtypes = [
        ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
    _icmp.IcmpSendEcho.restype = ctypes.c_ulong
    _INVALID_HANDLE = ctypes.c_void_p(-1).value


class IcmpPinger(BasePinger):
    """Real ICMP echo via the Windows IP Helper API: no admin rights, no
    ping.exe, no console windows."""

    def __init__(self, host):
        super().__init__(host)
        self.handle = _icmp.IcmpCreateFile()
        if not self.handle or self.handle == _INVALID_HANDLE:
            raise OSError("IcmpCreateFile failed")
        self.payload = b"quickping"
        self.buf = ctypes.create_string_buffer(
            ctypes.sizeof(IcmpEchoReply) + len(self.payload) + 72)

    def ping(self):
        ip = self.resolve()
        if ip is None:
            return None
        addr = struct.unpack("<L", socket.inet_aton(ip))[0]
        n = _icmp.IcmpSendEcho(self.handle, addr, self.payload,
                               len(self.payload), None, self.buf,
                               len(self.buf), int(TIMEOUT * 1000))
        if n:
            reply = IcmpEchoReply.from_buffer(self.buf)
            if reply.Status == 0:
                return float(reply.RoundTripTime)
        self.fail()
        return None

    def close(self):
        if self.handle:
            _icmp.IcmpCloseHandle(self.handle)
            self.handle = None


class SubprocessPinger(BasePinger):
    """Fallback for non-Windows systems (or if the IP Helper API fails)."""

    def ping(self):
        if IS_WIN:
            cmd, flags = ["ping", "-n", "1", "-w", "1000", self.host], 0x08000000
        else:
            cmd, flags = ["ping", "-c", "1", "-W", "1", self.host], 0
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=3, creationflags=flags).stdout
        except Exception:
            return None
        m = re.search(r"time[=<]\s*([\d.]+)", out)
        return float(m.group(1)) if m else None


class TcpPinger(BasePinger):
    """Time to complete a TCP handshake (SYN -> SYN/ACK). Works through
    networks that filter or rate-limit ICMP. A refused connection (RST)
    still counts: the host answered."""

    def __init__(self, host):
        super().__init__(host, 443)

    def ping(self):
        ip = self.resolve()
        if ip is None:
            return None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        try:  # close with RST so we don't pile up TIME_WAIT sockets
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack("ii", 1, 0))
        except OSError:
            pass
        ms = None
        try:
            t0 = time.perf_counter()
            err = s.connect_ex((ip, self.port))
            if err in (0, errno.ECONNREFUSED, 10061):
                ms = (time.perf_counter() - t0) * 1000
        except OSError:
            pass
        finally:
            s.close()
        if ms is None:
            self.fail()
        return ms


class UdpPinger(BasePinger):
    """Round trip of a tiny UDP DNS query (root NS lookup). UDP has no echo
    of its own, so this only works against DNS servers (8.8.8.8, 1.1.1.1,
    4.2.2.4 ...)."""

    TAIL = b"\x00" + struct.pack(">HH", 2, 1)  # QNAME ".", QTYPE NS, IN

    def __init__(self, host):
        super().__init__(host, 53)

    def ping(self):
        ip = self.resolve()
        if ip is None:
            return None
        qid = random.getrandbits(16)
        pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + self.TAIL
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        ms = None
        try:
            t0 = time.perf_counter()
            s.sendto(pkt, (ip, self.port))
            while time.perf_counter() - t0 < TIMEOUT:
                data, _ = s.recvfrom(512)
                if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                    ms = (time.perf_counter() - t0) * 1000
                    break
        except OSError:
            pass
        finally:
            s.close()
        if ms is None:
            self.fail()
        return ms


def make_pinger(method, host):
    if method == "tcp":
        return TcpPinger(host)
    if method == "udp":
        return UdpPinger(host)
    if IS_WIN:
        try:
            return IcmpPinger(host)
        except OSError:
            pass
    return SubprocessPinger(host)


# ==================== FORMAT HELPERS ====================


def format_bytes(n):
    mb = max(n, 0) / (1024 * 1024)
    return f"{mb / 1024:.2f} GB" if mb >= 1024 else f"{mb:.1f} MB"


def format_speed(bps):
    bps = max(bps, 0)
    if bps < 1024:
        return f"{bps:.0f} B/s"
    if bps < 1024 ** 2:
        return f"{bps / 1024:.1f} KB/s"
    if bps < 1024 ** 3:
        return f"{bps / 1024 ** 2:.2f} MB/s"
    return f"{bps / 1024 ** 3:.2f} GB/s"


def ping_color(ms):
    if ms <= 60:
        return "#0055FF"
    if ms <= 120:
        return "#00FF00"
    if ms <= 199:
        return "#FFFF00"
    return "#FF0000"


def loss_color(pct):
    if pct <= 0:
        return "#00FF00"
    return "#FFFF00" if pct < 10 else "#FF0000"


WAIT = object()  # "no result yet" marker

def design_h(n_targets):
    """Window height for n targets (5 targets -> 460, like the original)."""
    return 28 * n_targets + 320


# ==================== MAIN WINDOW ====================


class QuickPingHUD:
    def __init__(self, root):
        self.root = root
        root.title("Quick Ping HUD")
        root.configure(bg=BG)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.cfg = load_config()
        root.attributes("-topmost", self.cfg["topmost"])

        self.last_w = 300
        self.last_h = design_h(len(self.cfg["targets"]))
        root.geometry(f"{self.last_w}x{self.last_h}")

        self.cache = {}
        self.buttons = []
        self.right_items = []
        self.settings = None
        self._bg_job = None

        self.stop_event = threading.Event()
        self.results = {}
        self.loss_hist = {}

        self.target_interface = self.pick_real_interface()
        self.last_up = None
        self.prev = None
        self.last_io = None
        self.speed_hist = deque(maxlen=5)
        self.start_recv = self.start_sent = 0
        self.tick_count = 0

        self.fetching = False
        self.ip_state = ("IP: Fetching...", "#FFFF00", "Fetching...", "#FFFF00")

        # Optional background, pre-shrunk to keep memory low.
        self.bg_src = None
        if Image is not None:
            try:
                img = Image.open(resource_path("bg.jpg")).convert("RGB")
                img.thumbnail((640, 640))
                self.bg_src = img
            except Exception:
                pass
        self.bg_img = None
        self.bg_item = None

        self.canvas = tk.Canvas(root, highlightthickness=0, bg=BG)
        self.canvas.pack(fill="both", expand=True)

        self.f_ip = tkfont.Font(family=FONT, size=9, weight="bold")
        self.f_small = tkfont.Font(family=FONT, size=8, weight="bold")

        self.build_ui()
        self.reset_session()
        self.start_pingers()
        self.fetch_ip_async()

        root.bind("<Configure>", self.on_resize_event)
        self.tick()

    # ---------------- UI construction (same layout as the original) -----

    def fit(self, txt, font):
        """Shorten txt with an ellipsis so it never runs off the window."""
        maxw = self.last_w - 30
        if font.measure(txt) <= maxw:
            return txt
        while len(txt) > 1 and font.measure(txt + "\u2026") > maxw:
            txt = txt[:-1]
        return txt + "\u2026"

    def build_ui(self):
        c = self.canvas
        c.delete("all")
        self.cache.clear()
        self.right_items = []
        right_x = self.last_w - 15

        self.bg_item = None
        if self.bg_src:
            self.bg_item = c.create_image(0, 0, anchor="nw")
            self.apply_bg()

        def text(x, y, txt, fill, size, anchor="w", tags=()):
            return c.create_text(x, y, text=txt, fill=fill, anchor=anchor,
                                 tags=tags, font=(FONT, size, "bold"))

        # ping rows
        self.ping_ids = []
        y = 25
        for t in self.cfg["targets"]:
            text(15, y, t["name"], "#AAAAAA", 11)
            pid = text(right_x, y, "...", "#888888", 11, "e")
            self.ping_ids.append(pid)
            self.right_items.append(pid)
            y += 28

        # speed
        speed_y = y + 15
        self.dl_id = text(15, speed_y, "DL: 0 KB/s", "#FF8C00", 10)
        self.up_id = text(15, speed_y + 22, "UP: 0 KB/s", "#00BFFF", 10)

        # packet loss
        self.loss_y = speed_y + 52
        text(15, self.loss_y, "pk loss :", "#AAAAAA", 9)
        self.loss_id = text(right_x, self.loss_y, "--", "#888888", 10, "e")
        self.right_items.append(self.loss_id)

        # separator
        self.sep_y = self.loss_y + 28
        self.separator = c.create_line(15, self.sep_y, right_x, self.sep_y,
                                       fill="#333333")

        # totals + interface
        self.tdl_id = text(15, self.sep_y + 20, "TOTAL DL: 0 MB", "#FF8C00", 10)
        self.tup_id = text(15, self.sep_y + 42, "TOTAL UP: 0 MB", "#00BFFF", 10)
        self.iface_id = text(15, self.sep_y + 62, "", "#666666", 8)

        # IP + location
        ip_y = self.sep_y + 85
        self.ip_id = text(15, ip_y, self.fit(self.ip_state[0], self.f_ip),
                          "#00FFCC", 9, tags="ipbtn")
        self.loc_id = text(15, ip_y + 20, self.fit(self.ip_state[2], self.f_ip),
                           "#FFAA00", 9, tags="ipbtn")
        c.tag_bind("ipbtn", "<Button-1>", lambda e: self.fetch_ip_async())
        c.tag_bind("ipbtn", "<Enter>", lambda e: c.config(cursor="hand2"))
        c.tag_bind("ipbtn", "<Leave>", lambda e: c.config(cursor=""))

        # buttons
        for b in self.buttons:
            b.destroy()
        self.buttons = []

        def button(label, cmd, x):
            b = tk.Button(self.root, text=label, command=cmd, bg="#222222",
                          fg="#FFFFFF", activebackground="#444444",
                          activeforeground="white", relief="flat", bd=1,
                          font=(FONT, 8, "bold"))
            c.create_window(x, ip_y + 55, window=b, anchor="nw", width=120)
            self.buttons.append(b)

        button("RESET DATA", self.reset_session, 15)
        button("SETTINGS", self.open_settings, 145)

    def refresh(self):
        """Redraw current values right after a rebuild (no 1 s blank)."""
        self.update_pings()
        self.render_speed()
        self.update_ip()

    def apply_bg(self):
        if not (self.bg_src and self.bg_item):
            return
        img = self.bg_src.resize((max(self.last_w, 1), max(self.last_h, 1)),
                                 Image.Resampling.BILINEAR)
        self.bg_img = ImageTk.PhotoImage(img)
        self.canvas.itemconfig(self.bg_item, image=self.bg_img)

    def on_resize_event(self, event):
        if event.widget is not self.root:   # ignore child-widget events
            return
        if event.width == self.last_w and event.height == self.last_h:
            return
        self.last_w, self.last_h = event.width, event.height

        right_x = event.width - 15
        for item in self.right_items:
            co = self.canvas.coords(item)
            if len(co) == 2:
                self.canvas.coords(item, right_x, co[1])
        self.canvas.coords(self.separator, 15, self.sep_y, right_x, self.sep_y)

        if self._bg_job:                    # resize the image once dragging stops
            self.root.after_cancel(self._bg_job)
        self._bg_job = self.root.after(60, self.apply_bg)

    def set_item(self, item, text=None, fill=None):
        """itemconfig only when something actually changed."""
        key = (text, fill)
        if self.cache.get(item) == key:
            return
        self.cache[item] = key
        kw = {}
        if text is not None:
            kw["text"] = text
        if fill is not None:
            kw["fill"] = fill
        self.canvas.itemconfig(item, **kw)

    # ---------------- config / settings ----------------

    def apply_config(self, cfg):
        self.cfg = cfg
        err = save_config(cfg)
        self.root.attributes("-topmost", cfg["topmost"])
        self.last_h = design_h(len(cfg["targets"]))
        self.root.geometry(f"{self.last_w}x{self.last_h}")
        self.build_ui()
        self.start_pingers()
        self.refresh()
        return err

    def open_settings(self):
        if self.settings is not None and self.settings.win.winfo_exists():
            self.settings.win.lift()
            self.settings.win.focus_force()
            return
        self.settings = SettingsWindow(self)

    def on_close(self):
        self.stop_event.set()
        self.root.destroy()

    # ---------------- ping workers ----------------

    def start_pingers(self):
        self.stop_event.set()                # stop previous generation
        self.stop_event = ev = threading.Event()
        results = {}
        hist = {i: deque(maxlen=PACKET_LOSS_WINDOW)
                for i in range(len(self.cfg["targets"]))}
        self.results, self.loss_hist = results, hist
        interval = self.cfg["interval"]
        for i, t in enumerate(self.cfg["targets"]):
            threading.Thread(target=self.ping_worker, daemon=True,
                             args=(i, t, ev, results, hist[i], interval)).start()

    @staticmethod
    def ping_worker(i, target, ev, results, hist, interval):
        pinger = make_pinger(target["method"], target["host"])
        try:
            while not ev.is_set():
                t0 = time.monotonic()
                ms = pinger.ping()
                if ev.is_set():
                    break
                results[i] = ms
                hist.append(ms is not None)
                ev.wait(max(0.05, interval - (time.monotonic() - t0)))
        finally:
            pinger.close()

    # ---------------- periodic UI update ----------------

    def tick(self):
        try:
            self.update_pings()
            self.update_speed()
            self.update_ip()
            if self.tick_count % 5 == 0:
                self.check_adapters()
        except Exception as e:
            print("tick error:", e)
        self.tick_count += 1
        self.root.after(1000, self.tick)

    def update_pings(self):
        for i, item in enumerate(self.ping_ids):
            r = self.results.get(i, WAIT)
            if r is WAIT:
                self.set_item(item, "...", "#888888")
            elif r is None:
                self.set_item(item, "TIMEOUT", "#FF0000")
            else:
                label = "<1ms" if r < 1 else f"{r:.0f}ms"
                self.set_item(item, label, ping_color(r))

        hist = list(self.loss_hist.get(self.cfg["loss_index"], ()))
        if hist:
            pct = 100.0 * hist.count(False) / len(hist)
            self.set_item(self.loss_id, f"{pct:.0f}%", loss_color(pct))

    def update_speed(self):
        io = self.get_net_io()
        now = time.monotonic()
        if self.prev is not None:
            pt, pr, ps = self.prev
            dt = now - pt
            dr, ds = io.bytes_recv - pr, io.bytes_sent - ps
            if dr < 0 or ds < 0:            # counters reset (reconnect etc.)
                self.reset_session(io)
                self.speed_hist.clear()
            elif dt > 0.2:
                self.speed_hist.append((dr / dt, ds / dt))
        self.prev = (now, io.bytes_recv, io.bytes_sent)
        self.last_io = io
        self.render_speed()

    def render_speed(self):
        io = self.last_io
        if io is None:
            return
        if self.speed_hist:
            n = len(self.speed_hist)
            dl = sum(s[0] for s in self.speed_hist) / n
            up = sum(s[1] for s in self.speed_hist) / n
            self.set_item(self.dl_id, f"DL: {format_speed(dl)}")
            self.set_item(self.up_id, f"UP: {format_speed(up)}")
        self.set_item(self.tdl_id,
                      f"TOTAL DL: {format_bytes(io.bytes_recv - self.start_recv)}")
        self.set_item(self.tup_id,
                      f"TOTAL UP: {format_bytes(io.bytes_sent - self.start_sent)}")
        self.set_item(self.iface_id, self.fit(
            f"IFACE: {self.target_interface or 'ALL (fallback)'}", self.f_small))

    def update_ip(self):
        ip_t, ip_c, loc_t, loc_c = self.ip_state
        self.set_item(self.ip_id, self.fit(ip_t, self.f_ip), ip_c)
        self.set_item(self.loc_id, self.fit(loc_t, self.f_ip), loc_c)

    # ---------------- network interface handling ----------------

    def pick_real_interface(self):
        """Pick the busiest physical adapter that is up, so VPN/virtual
        adapters don't double-count traffic. None = use the sum of all."""
        try:
            stats = psutil.net_if_stats()
            counters = psutil.net_io_counters(pernic=True)
            best = None
            for name, st in stats.items():
                lname = name.lower()
                if not st.isup or lname == "lo":
                    continue
                if lname.startswith(VIRTUAL_PREFIX) or \
                        any(p in lname for p in VIRTUAL_SUBSTR):
                    continue
                io = counters.get(name)
                if io is None:
                    continue
                total = io.bytes_recv + io.bytes_sent
                if best is None or total > best[0]:
                    best = (total, name)
            if best:
                return best[1]
        except Exception as e:
            print("interface detection failed:", e)
        return None

    def get_net_io(self):
        if self.target_interface:
            per = psutil.net_io_counters(pernic=True)
            io = per.get(self.target_interface)
            if io is not None:
                return io
            self.target_interface = self.pick_real_interface()
            io = per.get(self.target_interface) if self.target_interface else None
            if io is not None:
                return io
        return psutil.net_io_counters()

    def check_adapters(self):
        try:
            up = frozenset(n for n, s in psutil.net_if_stats().items() if s.isup)
        except Exception:
            return
        if up == self.last_up:
            return
        first = self.last_up is None
        self.last_up = up
        if first:
            return
        new_iface = self.pick_real_interface()
        if new_iface != self.target_interface:
            self.target_interface = new_iface
            self.prev = None
            self.speed_hist.clear()
            self.reset_session()
        self.fetch_ip_async()

    def reset_session(self, io=None):
        io = io or self.get_net_io()
        self.start_recv, self.start_sent = io.bytes_recv, io.bytes_sent

    # ---------------- public IP lookup ----------------

    def fetch_ip_async(self):
        if self.fetching:
            return
        self.fetching = True
        self.ip_state = ("IP: Checking...", "#FFFF00", "Checking...", "#FFFF00")
        threading.Thread(target=self._fetch_ip, daemon=True).start()

    def _fetch_ip(self):
        try:
            req = urllib.request.Request(
                "http://ip-api.com/json/?fields=status,query,country,city,regionName",
                headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                info = json.load(r)
            if info.get("status") == "success":
                loc = f"{info.get('country', '?')} - " \
                      f"{info.get('city') or info.get('regionName', '?')}"
                self.ip_state = (f"IP: {info['query']}", "#00FFCC", loc, "#FFAA00")
            else:
                self.ip_state = ("IP: N/A", "#FF4444", "Lookup failed", "#FF4444")
        except Exception:
            self.ip_state = ("IP: N/A", "#FF4444", "No connection?", "#FF4444")
        finally:
            self.fetching = False


# ==================== SETTINGS WINDOW ====================


class SettingsWindow:
    LABELS = {"icmp": "ICMP", "tcp": "TCP", "udp": "UDP (DNS)"}
    FROM_LABEL = {v: k for k, v in LABELS.items()}
    FG, FIELD = "#DDDDDD", "#1E1E1E"

    def __init__(self, app):
        self.app = app
        self.rows = []
        self.next_id = 0

        w = self.win = tk.Toplevel(app.root)
        w.title("Quick Ping HUD - Settings")
        w.configure(bg=BG, padx=12, pady=10)
        w.resizable(False, False)
        w.transient(app.root)
        w.attributes("-topmost", True)
        w.geometry(f"+{app.root.winfo_x() + 30}+{app.root.winfo_y() + 30}")
        w.protocol("WM_DELETE_WINDOW", self.close)

        self.loss_var = tk.IntVar(value=-1)
        self.vcmd = (w.register(lambda p: len(p) <= NAME_MAX), "%P")

        # header
        head = tk.Frame(w, bg=BG)
        head.pack(anchor="w")
        for txt, width in (("Name", 14), ("Host / IP", 24), ("Method", 11),
                           ("Loss", 5)):
            tk.Label(head, text=txt, width=width, anchor="w", bg=BG,
                     fg="#888888", font=(FONT, 9, "bold")).pack(side="left", padx=2)

        self.rows_frame = tk.Frame(w, bg=BG)
        self.rows_frame.pack(anchor="w", pady=(2, 4))

        self.add_btn = self.make_button(w, "+ Add target", self.add_row_clicked)
        self.add_btn.pack(anchor="w", pady=(0, 8))

        # options
        opt = tk.Frame(w, bg=BG)
        opt.pack(anchor="w", fill="x")
        tk.Label(opt, text="Ping every", bg=BG, fg=self.FG,
                 font=(FONT, 9)).pack(side="left")
        self.interval_var = tk.StringVar()
        ttk.Combobox(opt, textvariable=self.interval_var, state="readonly",
                     width=6, values=[f"{i:g} s" for i in INTERVALS]
                     ).pack(side="left", padx=(6, 18))
        self.topmost_var = tk.BooleanVar()
        self.check(opt, "Always on top", self.topmost_var).pack(side="left")

        self.startup_var = tk.BooleanVar(value=is_startup_enabled())
        sc = self.check(w, "Start with Windows", self.startup_var)
        if not IS_WIN:
            sc.config(state="disabled")
        sc.pack(anchor="w", pady=(6, 0))

        tk.Label(w, bg=BG, fg="#777777", justify="left", wraplength=470,
                 font=(FONT, 8), text=(
                     "Host = name or IP, optionally with a port (google.com:443).\n"
                     "ICMP: classic ping.  TCP: handshake time (default port 443), "
                     "works where ICMP is filtered.  UDP: DNS query time (port 53), "
                     "only works against DNS servers such as 8.8.8.8.\n"
                     "Loss: the target used for the packet-loss readout.  "
                     f"Names are limited to {NAME_MAX} characters.")
                 ).pack(anchor="w", pady=(8, 8))

        # buttons
        bar = tk.Frame(w, bg=BG)
        bar.pack(anchor="e", fill="x")
        self.make_button(bar, "Restore defaults", self.restore_defaults
                         ).pack(side="left")
        self.make_button(bar, "Cancel", self.close).pack(side="right")
        self.make_button(bar, "Save", self.save, "#1F6F3A"
                         ).pack(side="right", padx=6)

        self.populate(app.cfg)

    # ---- widgets ----

    def make_button(self, parent, text, cmd, bg="#2A2A2A"):
        return tk.Button(parent, text=text, command=cmd, bg=bg, fg="white",
                         activebackground="#444444", activeforeground="white",
                         relief="flat", bd=1, padx=10, font=(FONT, 9, "bold"))

    def check(self, parent, text, var):
        return tk.Checkbutton(parent, text=text, variable=var, bg=BG,
                              fg=self.FG, selectcolor="#333333",
                              activebackground=BG, activeforeground="white",
                              font=(FONT, 9))

    def entry(self, parent, var, width, **kw):
        return tk.Entry(parent, textvariable=var, width=width, bg=self.FIELD,
                        fg="white", insertbackground="white", relief="flat",
                        font=(FONT, 9), **kw)

    # ---- rows ----

    def populate(self, cfg):
        for r in list(self.rows):
            r["frame"].destroy()
        self.rows.clear()
        for i, t in enumerate(cfg["targets"]):
            rid = self.add_row(t["name"], t["host"], t["method"])
            if i == cfg["loss_index"]:
                self.loss_var.set(rid)
        self.interval_var.set(f"{cfg['interval']:g} s")
        self.topmost_var.set(cfg["topmost"])

    def add_row_clicked(self):
        self.add_row()

    def add_row(self, name="", host="", method="icmp"):
        if len(self.rows) >= MAX_TARGETS:
            return None
        rid = self.next_id
        self.next_id += 1
        f = tk.Frame(self.rows_frame, bg=BG)
        f.pack(anchor="w", pady=1)
        row = {"id": rid, "frame": f, "name": tk.StringVar(value=name),
               "host": tk.StringVar(value=host),
               "method": tk.StringVar(value=self.LABELS.get(method, "ICMP"))}
        self.entry(f, row["name"], 14, validate="key",
                   validatecommand=self.vcmd).pack(side="left", padx=2)
        self.entry(f, row["host"], 24).pack(side="left", padx=2)
        ttk.Combobox(f, textvariable=row["method"], state="readonly", width=10,
                     values=list(self.LABELS.values())).pack(side="left", padx=2)
        tk.Radiobutton(f, variable=self.loss_var, value=rid, bg=BG,
                       selectcolor="#333333", activebackground=BG
                       ).pack(side="left", padx=(8, 4))
        tk.Button(f, text="x", width=2, bg="#3A1F1F", fg="white", relief="flat",
                  command=lambda: self.remove_row(rid)).pack(side="left", padx=2)
        self.rows.append(row)
        if self.loss_var.get() == -1:
            self.loss_var.set(rid)
        self.add_btn.config(state="normal" if len(self.rows) < MAX_TARGETS
                            else "disabled")
        return rid

    def remove_row(self, rid):
        if len(self.rows) <= 1:
            return
        row = next(r for r in self.rows if r["id"] == rid)
        row["frame"].destroy()
        self.rows.remove(row)
        if self.loss_var.get() == rid:
            self.loss_var.set(self.rows[0]["id"])
        self.add_btn.config(state="normal")

    # ---- actions ----

    def save(self):
        targets, loss_idx = [], 0
        for r in self.rows:
            host = r["host"].get().strip()
            if not host or not re.fullmatch(r"[A-Za-z0-9._:\-]+", host):
                messagebox.showwarning(
                    "Settings", "Every row needs a valid host or IP "
                    "(no spaces).", parent=self.win)
                return
            targets.append({
                "name": (r["name"].get().strip() or host)[:NAME_MAX],
                "host": host,
                "method": self.FROM_LABEL.get(r["method"].get(), "icmp"),
            })
            if r["id"] == self.loss_var.get():
                loss_idx = len(targets) - 1
        cfg = {"targets": targets, "loss_index": loss_idx,
               "interval": float(self.interval_var.get().split()[0]),
               "topmost": self.topmost_var.get()}
        err = self.app.apply_config(cfg)
        if err:
            messagebox.showwarning("Settings", f"Applied, but could not save "
                                   f"to disk:\n{err}", parent=self.win)
        if IS_WIN:
            try:
                set_startup(self.startup_var.get())
            except Exception as e:
                messagebox.showerror("Startup", f"Could not change startup "
                                     f"setting:\n{e}", parent=self.win)
        self.close()

    def restore_defaults(self):
        if not messagebox.askyesno(
                "Restore defaults", "Replace your targets with the default "
                "list?", parent=self.win):
            return
        self.app.apply_config(copy.deepcopy(DEFAULT_CONFIG))
        self.close()

    def close(self):
        self.win.destroy()


# ==================== MAIN ====================


def main():
    root = tk.Tk()
    QuickPingHUD(root)
    root.mainloop()


if __name__ == "__main__":
    main()
