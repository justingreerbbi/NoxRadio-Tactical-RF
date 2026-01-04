#!/usr/bin/env bash
# noxradio-install.sh
# APT-only (no pip) Direwolf + AX.25 + NoxRadio Tactical Web UI + REST API backend
#
# NEW IN THIS VERSION:
# - Settings page (rig config): app callsign override, manual lat/lon/telemetry, default group, display name
# - Optional: apply callsign to Direwolf (/etc/direwolf.conf) via root helper (safe chars only)
# - Secure mode: user sets a key; messages/beacons can be encrypted/decrypted (Fernet via python3-cryptography)
#   - Key is NOT stored in the browser
#   - DB stores only salt + key-check; actual derived key stays in memory (must re-enter after reboot)
# - Contacts/roster only populate for NOXRADIO payloads (NR1|...), not for normal APRS traffic
# - Message composer uses a multi-line auto-growing textarea (Shift+Enter for newline)
#
# Run:
#   chmod +x noxradio-install.sh
#   sudo ./noxradio-install.sh

# If invoked via `sh`/`dash`, re-exec under bash so bashisms work.
if [ -z "${BASH_VERSION:-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi

set -euo pipefail

LOG_TAG="[noxradio]"
DW_REPO="https://github.com/wb2osz/direwolf.git"
DW_SRC_DIR="/opt/direwolf-src"
DW_CONF="/etc/direwolf.conf"
DW_USER="direwolf"

NOXRADIO_USER="noxradio"
WEB_DIR="/opt/noxradio-web"
WEB_PORT="8080"
KISS_PORT="8001"

DATA_DIR="/var/lib/noxradio"
DB_PATH="${DATA_DIR}/noxradio.db"
LOG_DIR="/var/log/noxradio"

CACHE_MAX_EVENTS="800"

log()  { echo "${LOG_TAG} $*"; }
warn() { echo "${LOG_TAG} WARNING: $*" >&2; }
die()  { echo "${LOG_TAG} ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }
is_root()  { [[ "${EUID}" -eq 0 ]]; }

detect_primary_user() {
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    echo "${SUDO_USER}"
  else
    local u
    u="$(ls -1 /home 2>/dev/null | head -n 1 || true)"
    [[ -n "${u}" ]] && echo "${u}" || echo "pi"
  fi
}

apt_install() {
  local pkgs=("$@")
  log "Installing packages (apt): ${pkgs[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
}

# --- callsign prompt (ACCEPT ANYTHING) ---
prompt_callsign() {
  local existing=""
  if [[ -f "${DW_CONF}" ]]; then
    existing="$(sed -n 's/^MYCALL[[:space:]]\+\(.*\)$/\1/p' "${DW_CONF}" | head -n 1 || true)"
  fi
  existing="$(echo -n "${existing}" | tr -d ' \t\r\n')"

  {
    echo ""
    echo "============================================================"
    echo " Direwolf Callsign Setup"
    echo "============================================================"
    if [[ -n "${existing}" ]]; then
      echo "Current MYCALL in ${DW_CONF}: ${existing}"
    fi
    echo "Type ANY value you want. Press ENTER to keep the current/default."
    echo ""
  } >&2

  local input=""
  read -r -p "MYCALL [${existing:-N0CALL-10}]: " input || true
  input="$(echo -n "${input}" | tr -d ' \t\r\n')"

  if [[ -n "${input}" ]]; then
    echo "${input}"
  elif [[ -n "${existing}" ]]; then
    echo "${existing}"
  else
    echo "N0CALL-10"
  fi
}

# --- hardware detection (AIOC) ---
detect_audio_capture_card() {
  local line card
  line="$(arecord -l 2>/dev/null | grep -E 'card [0-9]+' | grep -viE 'bcm2835|vc4hdmi' | head -n 1 || true)"
  [[ -z "${line}" ]] && { echo ""; return; }
  card="$(echo "${line}" | sed -n 's/.*card \([0-9]\+\).*/\1/p' | head -n 1)"
  echo "${card}"
}

detect_ptt_hidraw_device() {
  local dev props
  for dev in /dev/hidraw*; do
    [[ -e "${dev}" ]] || continue
    props="$(udevadm info -q property -n "${dev}" 2>/dev/null || true)"
    if echo "${props}" | grep -qiE 'CM108|C-Media|Cmedia|USB Audio'; then
      echo "${dev}"
      return
    fi
  done
  for dev in /dev/hidraw*; do
    [[ -e "${dev}" ]] || continue
    echo "${dev}"
    return
  done
  echo ""
}

detect_serial_tty_device() {
  [[ -e /dev/ttyACM0 ]] && { echo "/dev/ttyACM0"; return; }
  [[ -e /dev/ttyUSB0 ]] && { echo "/dev/ttyUSB0"; return; }
  echo ""
}

udev_vid_pid_for_node() {
  local node="$1"
  [[ -n "${node}" && -e "${node}" ]] || { echo ""; return; }
  local props vid pid
  props="$(udevadm info -q property -n "${node}" 2>/dev/null || true)"
  vid="$(echo "${props}" | sed -n 's/^ID_VENDOR_ID=\(.*\)$/\1/p' | head -n 1)"
  pid="$(echo "${props}" | sed -n 's/^ID_MODEL_ID=\(.*\)$/\1/p' | head -n 1)"
  [[ -n "${vid}" && -n "${pid}" ]] && echo "${vid} ${pid}" || echo ""
}

write_udev_rules() {
  local hid_node="$1"
  local tty_node="$2"

  local rule_file="/etc/udev/rules.d/99-noxradio-aioc.rules"
  local hid_vp tty_vp hid_vid hid_pid tty_vid tty_pid

  hid_vp="$(udev_vid_pid_for_node "${hid_node}")"
  tty_vp="$(udev_vid_pid_for_node "${tty_node}")"

  {
    echo "# NoxRadio AIOC permissions (generated)"
    echo "# Allows non-root Direwolf access to hidraw (CM108-style PTT) and serial (DTR/RTS PTT)"
    echo ""

    if [[ -n "${hid_vp}" ]]; then
      hid_vid="$(echo "${hid_vp}" | awk '{print $1}')"
      hid_pid="$(echo "${hid_vp}" | awk '{print $2}')"
      echo "SUBSYSTEM==\"hidraw\", ATTRS{idVendor}==\"${hid_vid}\", ATTRS{idProduct}==\"${hid_pid}\", MODE=\"0660\", GROUP=\"input\""
    else
      echo "# hidraw VID/PID not detected; falling back to generic (may be too broad):"
      echo "SUBSYSTEM==\"hidraw\", MODE=\"0660\", GROUP=\"input\""
    fi

    if [[ -n "${tty_vp}" ]]; then
      tty_vid="$(echo "${tty_vp}" | awk '{print $1}')"
      tty_pid="$(echo "${tty_vp}" | awk '{print $2}')"
      echo "SUBSYSTEM==\"tty\", ATTRS{idVendor}==\"${tty_vid}\", ATTRS{idProduct}==\"${tty_pid}\", MODE=\"0660\", GROUP=\"dialout\""
    else
      echo "# tty VID/PID not detected; generic dialout permissions already handle /dev/ttyACM* and /dev/ttyUSB*"
    fi
  } > "${rule_file}"

  chmod 0644 "${rule_file}"
  udevadm control --reload-rules
  udevadm trigger
  log "Wrote udev rules: ${rule_file}"
}

# --- Direwolf install ---
install_direwolf() {
  if command -v direwolf >/dev/null 2>&1; then
    log "Direwolf already installed at: $(command -v direwolf)"
    return
  fi

  log "Installing Direwolf from source into /usr/local..."
  rm -rf "${DW_SRC_DIR}"
  git clone "${DW_REPO}" "${DW_SRC_DIR}"
  mkdir -p "${DW_SRC_DIR}/build"
  pushd "${DW_SRC_DIR}/build" >/dev/null
  cmake ..
  make -j2
  make install
  make install-conf || true
  popd >/dev/null

  need_cmd direwolf
  log "Direwolf installed: $(command -v direwolf)"
}

ensure_direwolf_user() {
  if id -u "${DW_USER}" >/dev/null 2>&1; then
    log "User ${DW_USER} exists"
  else
    log "Creating system user: ${DW_USER}"
    useradd -r -m -s /usr/sbin/nologin "${DW_USER}"
  fi
  usermod -aG audio,dialout,input "${DW_USER}" || true
}

write_direwolf_config() {
  local audio_card="$1"
  local hid_node="$2"
  local tty_node="$3"
  local mycall="$4"

  local adevice_line
  if [[ -n "${audio_card}" ]]; then
    adevice_line="ADEVICE plughw:${audio_card},0"
  else
    adevice_line="# ADEVICE plughw:1,0   # TODO: set correct card,device"
  fi

  local ptt_line ptt_comment
  if [[ -n "${hid_node}" ]]; then
    ptt_line="PTT CM108"
    ptt_comment="# Using CM108-style HID PTT (recommended for AIOC)"
  elif [[ -n "${tty_node}" ]]; then
    ptt_line="PTT ${tty_node} DTR -RTS"
    ptt_comment="# Using serial DTR/RTS PTT (fallback)"
  else
    ptt_line="# PTT CM108  # TODO: enable PTT once AIOC is detected"
    ptt_comment="# No hidraw/tty device detected at install time."
  fi

  cat > "${DW_CONF}" <<EOF
# /etc/direwolf.conf (generated by noxradio-install.sh)

${adevice_line}
ARATE 48000

MYCALL ${mycall}

CHANNEL 0

${ptt_comment}
${ptt_line}

KISSPORT ${KISS_PORT}
EOF

  chmod 0644 "${DW_CONF}"
  log "Wrote Direwolf config: ${DW_CONF}"
}

write_direwolf_service() {
  local svc="/etc/systemd/system/direwolf.service"
  cat > "${svc}" <<EOF
[Unit]
Description=Direwolf Soundcard TNC
After=network.target sound.target

[Service]
Type=simple
User=${DW_USER}
ExecStart=/usr/local/bin/direwolf -c ${DW_CONF} -t 0
Restart=on-failure
RestartSec=2
KillMode=control-group
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now direwolf
  log "Enabled + started direwolf.service"
}

# --- AX.25 / ROSE setup ---
write_modules_load() {
  local f="/etc/modules-load.d/noxradio.conf"
  cat > "${f}" <<'EOF'
# NoxRadio packet modules
ax25
rose
netrom
EOF
  chmod 0644 "${f}"

  modprobe ax25 2>/dev/null || true
  modprobe rose 2>/dev/null || true
  modprobe netrom 2>/dev/null || true

  log "Configured module autoload: ${f}"
}

write_axports() {
  local mycall="$1"
  local f="/etc/ax25/axports"
  local tmp
  tmp="$(mktemp)"

  mkdir -p /etc/ax25
  local repl="ax0 ${mycall} 9600 255 2 NoxRadio Direwolf KISS bridge"

  if [[ -f "${f}" ]]; then
    awk -v repl="${repl}" '
      BEGIN {found=0}
      /^[[:space:]]*ax0[[:space:]]/ {print repl; found=1; next}
      {print}
      END { if (!found) print repl }
    ' "${f}" > "${tmp}"
  else
    {
      echo "# NoxRadio AX.25 port (generated)"
      echo "${repl}"
    } > "${tmp}"
  fi

  mv "${tmp}" "${f}"
  chmod 0644 "${f}"
  log "Updated: ${f}"
}

write_ax25_bridge_script() {
  local script="/usr/local/sbin/noxradio-ax25-bridge.sh"
  cat > "${script}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

KISS_TCP_HOST="127.0.0.1"
KISS_TCP_PORT="8001"
PTY_LINK="/tmp/dwkiss"
AXPORT="ax0"
INET_ADDR="44.1.1.1"

log() { echo "[ax25-bridge] $*"; }

rm -f "${PTY_LINK}"

log "Starting socat PTY <-> TCP KISS (${KISS_TCP_HOST}:${KISS_TCP_PORT})"
socat -d -d pty,raw,echo=0,link="${PTY_LINK}" "tcp:${KISS_TCP_HOST}:${KISS_TCP_PORT}" &
SOCAT_PID=$!

for i in $(seq 1 30); do
  [[ -e "${PTY_LINK}" ]] && break
  sleep 0.2
done

if [[ ! -e "${PTY_LINK}" ]]; then
  kill "${SOCAT_PID}" 2>/dev/null || true
  exit 1
fi

log "Attaching KISS: ${PTY_LINK} -> ${AXPORT} (${INET_ADDR})"
kissattach "${PTY_LINK}" "${AXPORT}" "${INET_ADDR}" || true
ip link set "${AXPORT}" up || true

wait "${SOCAT_PID}"
EOF
  chmod 0755 "${script}"
  log "Wrote: ${script}"
}

write_ax25_bridge_service() {
  local svc="/etc/systemd/system/noxradio-ax25-bridge.service"
  cat > "${svc}" <<EOF
[Unit]
Description=NoxRadio AX.25 bridge (Direwolf KISS TCP -> ax0)
After=network.target direwolf.service
Wants=direwolf.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/sbin/noxradio-ax25-bridge.sh
Restart=on-failure
RestartSec=2
KillMode=control-group
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now noxradio-ax25-bridge
  log "Enabled + started noxradio-ax25-bridge.service"
}

# --- Web deps (APT ONLY) ---
install_web_deps_apt_only() {
  if apt-cache show python3-fastapi >/dev/null 2>&1 && apt-cache show python3-uvicorn >/dev/null 2>&1; then
    apt_install python3-fastapi python3-uvicorn
  else
    die "APT packages python3-fastapi and/or python3-uvicorn are not available on this OS release. (You requested apt-only; no pip fallback.)"
  fi

  # crypto (for secure mode)
  if apt-cache show python3-cryptography >/dev/null 2>&1; then
    apt_install python3-cryptography
  else
    die "APT package python3-cryptography not available. Secure mode requires it."
  fi

  python3 -c "import fastapi, uvicorn; import cryptography" >/dev/null 2>&1 || die "fastapi/uvicorn/cryptography not importable after apt install."
  log "Verified Python modules: fastapi + uvicorn + cryptography"
}

# --- Backend user + storage dirs ---
ensure_noxradio_user() {
  if id -u "${NOXRADIO_USER}" >/dev/null 2>&1; then
    log "User ${NOXRADIO_USER} exists"
  else
    log "Creating system user: ${NOXRADIO_USER}"
    useradd -r -m -d "${DATA_DIR}" -s /usr/sbin/nologin "${NOXRADIO_USER}"
  fi
  usermod -aG audio,dialout,input "${NOXRADIO_USER}" || true
}

setup_storage_dirs() {
  mkdir -p "${DATA_DIR}" "${LOG_DIR}"
  chown -R "${NOXRADIO_USER}:${NOXRADIO_USER}" "${DATA_DIR}" "${LOG_DIR}"
  chmod 0750 "${DATA_DIR}" "${LOG_DIR}"

  if [[ ! -f "${DB_PATH}" ]]; then
    sudo -u "${NOXRADIO_USER}" bash -lc "sqlite3 '${DB_PATH}' 'PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;'"
  fi
  chown "${NOXRADIO_USER}:${NOXRADIO_USER}" "${DB_PATH}"
  chmod 0640 "${DB_PATH}"
  log "Storage directory ready: ${DATA_DIR}"
}

# --- Root helper to update Direwolf MYCALL safely ---
write_direwolf_mycall_helper() {
  local helper="/usr/local/sbin/noxradio-set-dw-mycall.sh"
  cat > "${helper}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DW_CONF="/etc/direwolf.conf"
CALL="${1:-}"

if [[ -z "${CALL}" ]]; then
  echo "usage: $0 <CALLSIGN>" >&2
  exit 2
fi

# Safety: only allow simple characters for root-level file edit
# (App callsign override can be anything; Direwolf MYCALL should be normal-ish.)
if ! [[ "${CALL}" =~ ^[A-Za-z0-9-]{1,15}$ ]]; then
  echo "Refusing unsafe callsign for Direwolf MYCALL. Use only A-Z a-z 0-9 and '-' (max 15)." >&2
  exit 3
fi

if [[ -f "${DW_CONF}" ]]; then
  if grep -qE '^MYCALL[[:space:]]+' "${DW_CONF}"; then
    sed -i "s/^MYCALL[[:space:]].*/MYCALL ${CALL}/" "${DW_CONF}"
  else
    echo "" >> "${DW_CONF}"
    echo "MYCALL ${CALL}" >> "${DW_CONF}"
  fi
else
  echo "Missing ${DW_CONF}" >&2
  exit 4
fi

systemctl restart direwolf
echo "Updated Direwolf MYCALL to ${CALL} and restarted direwolf."
EOF
  chmod 0755 "${helper}"
  chown root:root "${helper}"
  log "Wrote helper: ${helper}"

  local sudoers="/etc/sudoers.d/noxradio"
  cat > "${sudoers}" <<EOF
# Allow noxradio web service to update Direwolf MYCALL safely
${NOXRADIO_USER} ALL=(root) NOPASSWD: /usr/local/sbin/noxradio-set-dw-mycall.sh
EOF
  chmod 0440 "${sudoers}"
  chown root:root "${sudoers}"
  log "Wrote sudoers: ${sudoers}"
}

# --- Web app (ATAK-inspired UI + REST/WS + SQLite/WAL + secure mode + settings) ---
write_web_app() {
  mkdir -p "${WEB_DIR}"
  cat > "${WEB_DIR}/app.py" <<'PY'
import asyncio
import base64
import json
import os
import re
import sqlite3
import subprocess
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import quote_plus, unquote_plus

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = FastAPI()

# --- KISS constants ---
FEND = 0xC0
FESC = 0xDB
TFEND = 0xDC
TFESC = 0xDD

# --- runtime state ---
clients: Set[WebSocket] = set()
_reader_task: Optional[asyncio.Task] = None
_tx_queue: "asyncio.Queue[bytes]" = asyncio.Queue(maxsize=400)

# --- storage config ---
DB_PATH = os.environ.get("NOXRADIO_DB_PATH", "/var/lib/noxradio/noxradio.db")
CACHE_MAX_EVENTS = int(os.environ.get("NOXRADIO_CACHE_MAX_EVENTS", "800"))
CACHE_MAX_RX = int(os.environ.get("NOXRADIO_CACHE_MAX_RX", "400"))

recent_events: Deque[dict] = deque(maxlen=CACHE_MAX_EVENTS)
recent_rx: Deque[dict] = deque(maxlen=CACHE_MAX_RX)

_db_lock = asyncio.Lock()
_state_lock = asyncio.Lock()

# Connection status for UI
dw_status: Dict[str, Any] = {"state": "disconnected", "host": "127.0.0.1", "port": 8001, "since_ts": 0}

# Nox payload prefix
NOX_PREFIX = "NR1|"

# Secure state (derived key lives in memory only)
_secure: Dict[str, Any] = {
    "enabled": False,         # from DB setting
    "has_key_check": False,   # from DB (means a key was provisioned at least once)
    "unlocked": False,        # true if user entered correct key this boot
}
_fernet: Optional[Fernet] = None

# Settings cache (authoritative copy in DB)
_settings: Dict[str, Any] = {
    "app_callsign": "",       # override source callsign for TX (can differ from direwolf MYCALL)
    "display_name": "RIG",
    "default_group": "ALL",
    "manual_lat": None,
    "manual_lon": None,
    "manual_speed": None,
    "manual_heading": None,
    "manual_altitude": None,
    "secure_enabled": 0,
}

# Safety for root helper (only for updating Direwolf)
_SAFE_DW_CALL_RE = re.compile(r"^[A-Za-z0-9-]{1,15}$")


def _utc_ts() -> int:
    return int(time.time())


def _db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _ensure_schema_blocking() -> None:
    conn = _db_connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
            INSERT OR IGNORE INTO meta (k, v) VALUES ('schema_version', '3');

            CREATE TABLE IF NOT EXISTS settings (
              k TEXT PRIMARY KEY,
              v TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS groups (
              group_id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              created_ts INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS nodes (
              node_id TEXT PRIMARY KEY,
              callsign TEXT,
              name TEXT,
              group_id TEXT,
              last_seen_ts INTEGER NOT NULL,
              lat REAL,
              lon REAL,
              speed REAL,
              heading REAL,
              altitude REAL,
              extra_json TEXT,
              FOREIGN KEY(group_id) REFERENCES groups(group_id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen_ts);
            CREATE INDEX IF NOT EXISTS idx_nodes_group ON nodes(group_id);

            CREATE TABLE IF NOT EXISTS messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts INTEGER NOT NULL,
              direction TEXT NOT NULL,          -- rx/tx/local
              chat_type TEXT NOT NULL,          -- direct/group/raw
              chat_id TEXT NOT NULL,            -- direct: peer callsign, group: group_id, raw: "raw"
              src TEXT,
              dst TEXT,
              group_id TEXT,
              body TEXT NOT NULL,
              raw_bytes BLOB
            );
            CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts);
            CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_type, chat_id, ts);

            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts INTEGER NOT NULL,
              level TEXT NOT NULL,              -- info/warn/error
              message TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            """
        )

        now = _utc_ts()
        conn.execute("INSERT OR IGNORE INTO groups (group_id, name, created_ts) VALUES (?, ?, ?)", ("ALL", "ALL", now))

        # default settings
        defaults = {
            "app_callsign": "",
            "display_name": "RIG",
            "default_group": "ALL",
            "manual_lat": "",
            "manual_lon": "",
            "manual_speed": "",
            "manual_heading": "",
            "manual_altitude": "",
            "secure_enabled": "0",
            # secure key material (no plaintext key stored):
            "secure_salt_b64": "",
            "secure_keycheck_b64": "",
            "secure_kdf_iter": "200000",
        }
        for k, v in defaults.items():
            conn.execute("INSERT OR IGNORE INTO settings (k, v) VALUES (?, ?)", (k, v))

    finally:
        conn.close()


async def ensure_schema() -> None:
    await asyncio.to_thread(_ensure_schema_blocking)


def kiss_unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == FESC and i + 1 < len(data):
            nxt = data[i + 1]
            if nxt == TFEND:
                out.append(FEND); i += 2; continue
            if nxt == TFESC:
                out.append(FESC); i += 2; continue
        out.append(b); i += 1
    return bytes(out)


def kiss_escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b == FEND:
            out.extend([FESC, TFEND])
        elif b == FESC:
            out.extend([FESC, TFESC])
        else:
            out.append(b)
    return bytes(out)


def parse_callsign(callsign: str) -> Tuple[str, int]:
    cs = callsign.strip()
    if "-" in cs:
        call, ssid_str = cs.split("-", 1)
        try:
            ssid = int(ssid_str)
        except ValueError:
            ssid = 0
        return call.upper(), max(0, min(ssid, 15))
    return cs.upper(), 0


def ax25_addr_encode(call: str, ssid: int, last: bool) -> bytes:
    call = call.upper()[:6].ljust(6)
    addr = bytearray((ord(c) << 1) & 0xFE for c in call)
    ssid_byte = 0x60 | ((ssid & 0x0F) << 1)
    if last:
        ssid_byte |= 0x01
    addr.append(ssid_byte)
    return bytes(addr)


def ax25_addr_decode(addr7: bytes) -> Tuple[str, int, bool]:
    call = ""
    for c in addr7[0:6]:
        ch = (c >> 1) & 0x7F
        if ch != 0x20:
            call += chr(ch)
    ssid = (addr7[6] >> 1) & 0x0F
    last = bool(addr7[6] & 0x01)
    return call, ssid, last


def _get_direwolf_mycall() -> str:
    try:
        with open("/etc/direwolf.conf", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.upper().startswith("MYCALL"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1].strip()
    except OSError:
        pass
    return "N0CALL-10"


def _tx_src_callsign() -> str:
    cs = str(_settings.get("app_callsign") or "").strip()
    if cs:
        return cs
    return _get_direwolf_mycall()


def build_ax25_ui_frame(payload_text: str, src_callsign: str) -> bytes:
    src_call, src_ssid = parse_callsign(src_callsign)
    dest_call, dest_ssid = parse_callsign(os.environ.get("DIREWOLF_AX25_DEST", "APRS"))

    addrs = bytearray()
    addrs += ax25_addr_encode(dest_call, dest_ssid, last=False)
    addrs += ax25_addr_encode(src_call, src_ssid, last=True)

    control = bytes([0x03])
    pid = bytes([0xF0])
    info = payload_text.encode("utf-8", errors="replace")
    return bytes(addrs) + control + pid + info


def build_kiss_frame(ax25_frame: bytes) -> bytes:
    cmd = bytes([0x00])
    escaped = kiss_escape(cmd + ax25_frame)
    return bytes([FEND]) + escaped + bytes([FEND])


def parse_ax25_ui(frame: bytes) -> Optional[Dict[str, Any]]:
    if len(frame) < 16:
        return None

    i = 0
    dest, dest_ssid, _ = ax25_addr_decode(frame[i:i+7]); i += 7
    src, src_ssid, last = ax25_addr_decode(frame[i:i+7]); i += 7

    path = []
    while not last:
        if i + 7 > len(frame):
            return None
        digi, digi_ssid, last = ax25_addr_decode(frame[i:i+7]); i += 7
        path.append(f"{digi}-{digi_ssid}" if digi_ssid else digi)

    if i + 2 > len(frame):
        return None
    control = frame[i]; pid = frame[i+1]; i += 2

    if control != 0x03 or pid != 0xF0:
        return None

    payload = frame[i:].decode("ascii", errors="replace")

    src_str = f"{src}-{src_ssid}" if src_ssid else src
    dest_str = f"{dest}-{dest_ssid}" if dest_ssid else dest
    tnc2 = f"{src_str}>{dest_str}"
    if path:
        tnc2 += f",{','.join(path)}"
    tnc2 += f":{payload}"

    return {"src": src_str, "dst": dest_str, "path": path, "payload": payload, "tnc2": tnc2}


def _kv_parse(parts: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for p in parts:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        k = k.strip()
        v = unquote_plus(v.strip())
        if k:
            out[k] = v
    return out


def parse_nox_payload(payload: str) -> Optional[Dict[str, Any]]:
    if not payload.startswith(NOX_PREFIX):
        return None
    parts = payload.split("|")
    if len(parts) < 2:
        return None
    msg_type = parts[1].strip().upper()  # B / DM / GM
    kv = _kv_parse(parts[2:])
    return {"nox": True, "type": msg_type, "kv": kv}


def _json_compact(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _derive_fernet(passphrase: str, salt: bytes, iterations: int) -> Fernet:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
    return Fernet(key)


def _secure_can_decrypt() -> bool:
    return bool(_secure.get("enabled")) and bool(_secure.get("unlocked")) and (_fernet is not None)


def _secure_encrypt_json(obj: Any) -> str:
    if not _secure_can_decrypt():
        raise RuntimeError("secure mode is enabled but key is not unlocked")
    token = _fernet.encrypt(_json_compact(obj).encode("utf-8"))
    return token.decode("ascii")


def _secure_decrypt_json(token: str) -> Any:
    if not _secure_can_decrypt():
        raise RuntimeError("secure mode is enabled but key is not unlocked")
    data = _fernet.decrypt(token.encode("ascii"))
    return json.loads(data.decode("utf-8", errors="replace"))


def build_nox_beacon(gid: str) -> str:
    gid = (gid or _settings.get("default_group") or "ALL").strip().upper() or "ALL"

    # If secure enabled, encrypt the telemetry JSON. Otherwise send plaintext lat/lon fields.
    lat = _settings.get("manual_lat")
    lon = _settings.get("manual_lon")
    spd = _settings.get("manual_speed")
    hdg = _settings.get("manual_heading")
    alt = _settings.get("manual_altitude")
    name = str(_settings.get("display_name") or "").strip() or "RIG"

    if _secure.get("enabled"):
        token = _secure_encrypt_json({
            "lat": lat, "lon": lon, "spd": spd, "hdg": hdg, "alt": alt, "name": name
        })
        return "|".join(["NR1", "B", f"gid={quote_plus(gid)}", "enc=1", f"ct={quote_plus(token)}"])

    fields = ["NR1", "B", f"gid={quote_plus(gid)}"]
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
        fields.append(f"lat={lat:.6f}")
        fields.append(f"lon={lon:.6f}")
    if isinstance(spd, (int, float)): fields.append(f"spd={float(spd):.1f}")
    if isinstance(hdg, (int, float)): fields.append(f"hdg={float(hdg):.0f}")
    if isinstance(alt, (int, float)): fields.append(f"alt={float(alt):.1f}")
    if name: fields.append(f"name={quote_plus(name)}")
    return "|".join(fields)


def build_nox_dm(to_call: str, text: str) -> str:
    if _secure.get("enabled"):
        token = _secure_encrypt_json({"text": text})
        return "|".join(["NR1", "DM", f"to={quote_plus(to_call)}", "enc=1", f"ct={quote_plus(token)}"])
    return "|".join(["NR1", "DM", f"to={quote_plus(to_call)}", f"text={quote_plus(text)}"])


def build_nox_gm(gid: str, text: str) -> str:
    gid = (gid or "ALL").strip().upper() or "ALL"
    if _secure.get("enabled"):
        token = _secure_encrypt_json({"text": text})
        return "|".join(["NR1", "GM", f"gid={quote_plus(gid)}", "enc=1", f"ct={quote_plus(token)}"])
    return "|".join(["NR1", "GM", f"gid={quote_plus(gid)}", f"text={quote_plus(text)}"])


async def db_insert_event(level: str, message: str) -> None:
    ts = _utc_ts()
    recent_events.append({"ts": ts, "level": level, "message": message})

    async with _db_lock:
        def _write():
            conn = _db_connect()
            try:
                conn.execute("INSERT INTO events (ts, level, message) VALUES (?, ?, ?)", (ts, level, message))
            finally:
                conn.close()
        await asyncio.to_thread(_write)


async def db_insert_message(direction: str, chat_type: str, chat_id: str,
                            src: Optional[str], dst: Optional[str], group_id: Optional[str],
                            body: str, raw: Optional[bytes]) -> None:
    ts = _utc_ts()
    async with _db_lock:
        def _write():
            conn = _db_connect()
            try:
                conn.execute(
                    """
                    INSERT INTO messages (ts, direction, chat_type, chat_id, src, dst, group_id, body, raw_bytes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ts, direction, chat_type, chat_id, src, dst, group_id, body, raw),
                )
            finally:
                conn.close()
        await asyncio.to_thread(_write)


async def db_upsert_node(node_id: str, callsign: str, name: Optional[str], group_id: Optional[str],
                         lat: Optional[float], lon: Optional[float], speed: Optional[float],
                         heading: Optional[float], altitude: Optional[float], extra: Optional[dict]) -> None:
    ts = _utc_ts()
    extra_json = json.dumps(extra or {}, separators=(",", ":"))

    async with _db_lock:
        def _write():
            conn = _db_connect()
            try:
                conn.execute(
                    """
                    INSERT INTO nodes (node_id, callsign, name, group_id, last_seen_ts, lat, lon, speed, heading, altitude, extra_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(node_id) DO UPDATE SET
                      callsign=excluded.callsign,
                      name=COALESCE(excluded.name, nodes.name),
                      group_id=COALESCE(excluded.group_id, nodes.group_id),
                      last_seen_ts=excluded.last_seen_ts,
                      lat=COALESCE(excluded.lat, nodes.lat),
                      lon=COALESCE(excluded.lon, nodes.lon),
                      speed=COALESCE(excluded.speed, nodes.speed),
                      heading=COALESCE(excluded.heading, nodes.heading),
                      altitude=COALESCE(excluded.altitude, nodes.altitude),
                      extra_json=excluded.extra_json
                    """,
                    (node_id, callsign, name, group_id, ts, lat, lon, speed, heading, altitude, extra_json),
                )
            finally:
                conn.close()
        await asyncio.to_thread(_write)


async def db_get_groups() -> List[dict]:
    async with _db_lock:
        def _read():
            conn = _db_connect()
            try:
                cur = conn.execute("SELECT group_id, name FROM groups ORDER BY group_id ASC")
                return [{"group_id": r[0], "name": r[1]} for r in cur.fetchall()]
            finally:
                conn.close()
        return await asyncio.to_thread(_read)


async def db_get_nodes() -> List[dict]:
    async with _db_lock:
        def _read():
            conn = _db_connect()
            try:
                cur = conn.execute(
                    """
                    SELECT node_id, callsign, name, group_id, last_seen_ts, lat, lon, speed, heading, altitude
                    FROM nodes
                    ORDER BY last_seen_ts DESC
                    LIMIT 500
                    """
                )
                rows = cur.fetchall()
                out = []
                for r in rows:
                    out.append({
                        "node_id": r[0], "callsign": r[1], "name": r[2], "group_id": r[3],
                        "last_seen_ts": r[4], "lat": r[5], "lon": r[6], "speed": r[7], "heading": r[8], "altitude": r[9]
                    })
                return out
            finally:
                conn.close()
        return await asyncio.to_thread(_read)


async def db_get_messages(chat_type: str, chat_id: str, limit: int = 120) -> List[dict]:
    limit = max(1, min(limit, 300))
    async with _db_lock:
        def _read():
            conn = _db_connect()
            try:
                cur = conn.execute(
                    """
                    SELECT ts, direction, chat_type, chat_id, src, dst, group_id, body
                    FROM messages
                    WHERE chat_type=? AND chat_id=?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (chat_type, chat_id, limit),
                )
                rows = cur.fetchall()
                rows.reverse()
                out = []
                for r in rows:
                    out.append({
                        "ts": r[0], "direction": r[1], "chat_type": r[2], "chat_id": r[3],
                        "src": r[4], "dst": r[5], "group_id": r[6], "body": r[7]
                    })
                return out
            finally:
                conn.close()
        msgs = await asyncio.to_thread(_read)

    # Decrypt on the fly if needed
    if _secure_can_decrypt():
        for m in msgs:
            b = m.get("body") or ""
            if b.startswith("ENC:"):
                token = b[4:]
                try:
                    obj = _secure_decrypt_json(token)
                    if isinstance(obj, dict) and "text" in obj:
                        m["body"] = str(obj["text"])
                    else:
                        m["body"] = "[decrypted]"
                except Exception:
                    m["body"] = "[encrypted]"
    else:
        for m in msgs:
            if (m.get("body") or "").startswith("ENC:"):
                m["body"] = "[encrypted]"
    return msgs


async def db_get_settings() -> Dict[str, str]:
    async with _db_lock:
        def _read():
            conn = _db_connect()
            try:
                cur = conn.execute("SELECT k, v FROM settings")
                return {r[0]: r[1] for r in cur.fetchall()}
            finally:
                conn.close()
        return await asyncio.to_thread(_read)


async def db_set_settings(pairs: Dict[str, str]) -> None:
    async with _db_lock:
        def _write():
            conn = _db_connect()
            try:
                for k, v in pairs.items():
                    conn.execute("INSERT INTO settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
            finally:
                conn.close()
        await asyncio.to_thread(_write)


async def ws_broadcast(event: dict) -> None:
    msg = json.dumps(event, separators=(",", ":"))
    dead = []
    for ws in clients:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)


async def set_dw_status(state: str, host: str, port: int) -> None:
    async with _state_lock:
        dw_status.update({"state": state, "host": host, "port": port, "since_ts": _utc_ts()})
    await ws_broadcast({"type": "status", "dw": dw_status, "secure": _secure_summary(), "settings": _settings_public()})


def _settings_public() -> Dict[str, Any]:
    return {
        "app_callsign": _settings.get("app_callsign") or "",
        "display_name": _settings.get("display_name") or "RIG",
        "default_group": _settings.get("default_group") or "ALL",
        "manual_lat": _settings.get("manual_lat"),
        "manual_lon": _settings.get("manual_lon"),
        "manual_speed": _settings.get("manual_speed"),
        "manual_heading": _settings.get("manual_heading"),
        "manual_altitude": _settings.get("manual_altitude"),
    }


def _secure_summary() -> Dict[str, Any]:
    return {
        "enabled": bool(_secure.get("enabled")),
        "has_key_check": bool(_secure.get("has_key_check")),
        "unlocked": bool(_secure.get("unlocked")),
    }


def _direwolf_host_port() -> Tuple[str, int]:
    host = os.environ.get("DIREWOLF_KISS_HOST", "127.0.0.1")
    port_str = os.environ.get("DIREWOLF_KISS_PORT", "8001")
    try:
        port = int(port_str)
    except ValueError:
        port = 8001
    return host, port


async def _tx_loop(writer: asyncio.StreamWriter) -> None:
    while True:
        frame = await _tx_queue.get()
        writer.write(frame)
        await writer.drain()


async def enqueue_payload_for_tx(payload: str) -> None:
    payload = (payload or "").strip()
    if not payload:
        return

    src = _tx_src_callsign()
    ax25 = build_ax25_ui_frame(payload, src_callsign=src)
    kiss = build_kiss_frame(ax25)

    try:
        _tx_queue.put_nowait(kiss)
    except asyncio.QueueFull:
        await db_insert_event("warn", "TX queue full; dropping")
        await ws_broadcast({"type": "event", "level": "warn", "message": "TX queue full; dropping"})
        return


async def _load_settings_into_memory() -> None:
    s = await db_get_settings()

    _settings["app_callsign"] = s.get("app_callsign", "")
    _settings["display_name"] = s.get("display_name", "RIG") or "RIG"
    _settings["default_group"] = (s.get("default_group", "ALL") or "ALL").upper()

    def fnum(x: str) -> Optional[float]:
        x = (x or "").strip()
        if not x:
            return None
        try:
            return float(x)
        except Exception:
            return None

    _settings["manual_lat"] = fnum(s.get("manual_lat", ""))
    _settings["manual_lon"] = fnum(s.get("manual_lon", ""))
    _settings["manual_speed"] = fnum(s.get("manual_speed", ""))
    _settings["manual_heading"] = fnum(s.get("manual_heading", ""))
    _settings["manual_altitude"] = fnum(s.get("manual_altitude", ""))

    _secure["enabled"] = (s.get("secure_enabled", "0") == "1")
    _secure["has_key_check"] = bool((s.get("secure_keycheck_b64", "") or "").strip())
    _secure["unlocked"] = False

    global _fernet
    _fernet = None


async def _apply_direwolf_mycall_if_requested(new_call: str) -> Tuple[bool, str]:
    # Runs root helper via sudo (allowed by /etc/sudoers.d/noxradio)
    if not _SAFE_DW_CALL_RE.match(new_call or ""):
        return False, "Rejected for Direwolf update (unsafe chars). App callsign saved, Direwolf MYCALL unchanged."

    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            ["sudo", "/usr/local/sbin/noxradio-set-dw-mycall.sh", new_call],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode == 0:
            return True, (proc.stdout.strip() or "Direwolf MYCALL updated.")
        return False, (proc.stderr.strip() or proc.stdout.strip() or f"Helper failed rc={proc.returncode}")
    except Exception as e:
        return False, f"Failed to run helper: {e}"


async def direwolf_reader() -> None:
    host, port = _direwolf_host_port()

    while True:
        writer: Optional[asyncio.StreamWriter] = None
        tx_task: Optional[asyncio.Task] = None
        try:
            await set_dw_status("connecting", host, port)
            reader, writer = await asyncio.open_connection(host, port)

            await set_dw_status("connected", host, port)
            await db_insert_event("info", f"Connected to Direwolf KISS TCP at {host}:{port}")
            await ws_broadcast({"type": "event", "level": "info", "message": f"Connected to Direwolf KISS TCP at {host}:{port}"})

            tx_task = asyncio.create_task(_tx_loop(writer))
            buf = bytearray()

            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=1.0)
                except asyncio.TimeoutError:
                    chunk = b""

                if chunk == b"" and reader.at_eof():
                    raise ConnectionError("Direwolf closed KISS TCP")

                if chunk:
                    buf.extend(chunk)

                while True:
                    start = buf.find(bytes([FEND]))
                    if start == -1:
                        if len(buf) > 8192:
                            del buf[:-8192]
                        break
                    if start > 0:
                        del buf[:start]

                    end = buf.find(bytes([FEND]), start + 1)
                    if end == -1:
                        break

                    raw = bytes(buf[start + 1:end])
                    del buf[:end + 1]
                    if not raw:
                        continue

                    cmd = raw[0]
                    data = kiss_unescape(raw[1:])
                    kiss_cmd = cmd & 0x0F
                    if kiss_cmd != 0x00:
                        continue

                    parsed = parse_ax25_ui(data)
                    if not parsed:
                        continue

                    rx_evt = {"type": "rx", "ts": _utc_ts(), **parsed}
                    recent_rx.append(rx_evt)

                    # Always store raw RX (so you can monitor APRS too)
                    await db_insert_message("rx", "raw", "raw", parsed["src"], parsed["dst"], None, parsed["tnc2"], data)
                    await ws_broadcast(rx_evt)

                    # Only populate roster/contacts for NOXRADIO payloads:
                    nox = parse_nox_payload(parsed["payload"])
                    if not nox:
                        continue

                    kv = nox["kv"]
                    typ = nox["type"]
                    src = parsed["src"]

                    # Mark node as NOX participant (even if we can't decrypt content)
                    await db_upsert_node(
                        node_id=src,
                        callsign=src,
                        name=None,
                        group_id=None,
                        lat=None, lon=None,
                        speed=None, heading=None, altitude=None,
                        extra={"nox": True, "last": typ},
                    )

                    if typ == "B":
                        gid = (kv.get("gid") or "ALL").strip().upper() or "ALL"

                        if kv.get("enc") == "1" and "ct" in kv:
                            # Encrypted beacon
                            token = kv.get("ct", "")
                            if _secure_can_decrypt():
                                try:
                                    obj = _secure_decrypt_json(token)
                                    lat = obj.get("lat"); lon = obj.get("lon")
                                    spd = obj.get("spd"); hdg = obj.get("hdg"); alt = obj.get("alt"); name = obj.get("name")
                                except Exception:
                                    continue
                            else:
                                # Can't plot without key
                                continue
                        else:
                            # Plain beacon
                            try:
                                lat = float(kv.get("lat", "nan"))
                                lon = float(kv.get("lon", "nan"))
                                if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                                    raise ValueError("lat/lon out of range")
                            except Exception:
                                continue
                            spd = float(kv["spd"]) if "spd" in kv else None
                            hdg = float(kv["hdg"]) if "hdg" in kv else None
                            alt = float(kv["alt"]) if "alt" in kv else None
                            name = kv.get("name")

                        await db_upsert_node(
                            node_id=src,
                            callsign=src,
                            name=name,
                            group_id=gid,
                            lat=float(lat) if lat is not None else None,
                            lon=float(lon) if lon is not None else None,
                            speed=float(spd) if spd is not None else None,
                            heading=float(hdg) if hdg is not None else None,
                            altitude=float(alt) if alt is not None else None,
                            extra={"nox": True, "type": "B"},
                        )

                        evt = {
                            "type": "beacon",
                            "ts": _utc_ts(),
                            "node": {
                                "node_id": src, "callsign": src, "name": name, "group_id": gid,
                                "lat": float(lat) if lat is not None else None,
                                "lon": float(lon) if lon is not None else None,
                                "speed": float(spd) if spd is not None else None,
                                "heading": float(hdg) if hdg is not None else None,
                                "altitude": float(alt) if alt is not None else None,
                            }
                        }
                        await ws_broadcast(evt)

                    elif typ == "DM":
                        to_call = (kv.get("to") or "").strip().upper()
                        if not to_call:
                            continue

                        if kv.get("enc") == "1" and "ct" in kv:
                            body = "ENC:" + kv.get("ct", "")
                        else:
                            body = (kv.get("text") or "").strip()
                            if not body:
                                continue

                        chat_id = src  # RX chats keyed by sender
                        await db_insert_message("rx", "direct", chat_id, src, to_call, None, body, None)

                        # Broadcast decrypted (if possible)
                        disp = body
                        if body.startswith("ENC:") and _secure_can_decrypt():
                            try:
                                obj = _secure_decrypt_json(body[4:])
                                disp = str(obj.get("text", "[decrypted]"))
                            except Exception:
                                disp = "[encrypted]"
                        elif body.startswith("ENC:"):
                            disp = "[encrypted]"

                        await ws_broadcast({"type": "chat", "chat_type": "direct", "chat_id": chat_id, "ts": _utc_ts(),
                                            "direction": "rx", "src": src, "dst": to_call, "body": disp})

                    elif typ == "GM":
                        gid = (kv.get("gid") or "ALL").strip().upper() or "ALL"

                        if kv.get("enc") == "1" and "ct" in kv:
                            body = "ENC:" + kv.get("ct", "")
                        else:
                            body = (kv.get("text") or "").strip()
                            if not body:
                                continue

                        await db_insert_message("rx", "group", gid, src, None, gid, body, None)

                        disp = body
                        if body.startswith("ENC:") and _secure_can_decrypt():
                            try:
                                obj = _secure_decrypt_json(body[4:])
                                disp = str(obj.get("text", "[decrypted]"))
                            except Exception:
                                disp = "[encrypted]"
                        elif body.startswith("ENC:"):
                            disp = "[encrypted]"

                        await ws_broadcast({"type": "chat", "chat_type": "group", "chat_id": gid, "ts": _utc_ts(),
                                            "direction": "rx", "src": src, "group_id": gid, "body": disp})

        except Exception as e:
            await set_dw_status("error", host, port)
            await db_insert_event("error", f"Direwolf connection error: {e}. Retrying in 2s...")
            await ws_broadcast({"type": "event", "level": "error", "message": f"Direwolf connection error: {e}. Retrying in 2s..."})
            await asyncio.sleep(2)
        finally:
            try:
                if tx_task is not None:
                    tx_task.cancel()
            except Exception:
                pass
            try:
                if writer is not None:
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                pass


@app.on_event("startup")
async def _startup():
    await ensure_schema()
    await _load_settings_into_memory()
    await db_insert_event("info", "NoxRadio backend started")
    await ws_broadcast({"type": "event", "level": "info", "message": "NoxRadio backend started"})


@app.get("/health")
def health():
    return JSONResponse({"ok": True, "dw": dw_status, "secure": _secure_summary(), "settings": _settings_public()})


@app.get("/api/bootstrap")
async def api_bootstrap():
    groups = await db_get_groups()
    nodes = await db_get_nodes()
    return JSONResponse({
        "groups": groups,
        "nodes": nodes,
        "dw": dw_status,
        "secure": _secure_summary(),
        "settings": _settings_public()
    })


@app.get("/api/groups")
async def api_groups():
    return JSONResponse({"groups": await db_get_groups()})


@app.post("/api/groups")
async def api_groups_create(body: dict):
    group_id = str(body.get("group_id", "")).strip().upper()
    name = str(body.get("name", "")).strip() or group_id
    if not group_id:
        return JSONResponse({"ok": False, "error": "group_id required"}, status_code=400)

    ts = _utc_ts()
    async with _db_lock:
        def _write():
            conn = _db_connect()
            try:
                conn.execute("INSERT OR IGNORE INTO groups (group_id, name, created_ts) VALUES (?, ?, ?)", (group_id, name, ts))
                conn.execute("UPDATE groups SET name=? WHERE group_id=?", (name, group_id))
            finally:
                conn.close()
        await asyncio.to_thread(_write)

    await ws_broadcast({"type": "groups_updated"})
    return JSONResponse({"ok": True})


@app.get("/api/nodes")
async def api_nodes():
    return JSONResponse({"nodes": await db_get_nodes()})


@app.get("/api/messages")
async def api_messages(chat_type: str, chat_id: str, limit: int = 120):
    chat_type = (chat_type or "").strip()
    chat_id = (chat_id or "").strip()
    if chat_type not in ("direct", "group", "raw"):
        return JSONResponse({"ok": False, "error": "chat_type must be direct|group|raw"}, status_code=400)
    if not chat_id:
        return JSONResponse({"ok": False, "error": "chat_id required"}, status_code=400)
    msgs = await db_get_messages(chat_type, chat_id, limit=limit)
    return JSONResponse({"messages": msgs, "secure": _secure_summary()})


@app.get("/api/settings")
async def api_settings_get():
    return JSONResponse({"settings": _settings_public(), "secure": _secure_summary(), "direwolf_mycall": _get_direwolf_mycall()})


@app.post("/api/settings")
async def api_settings_set(body: dict):
    # Saves settings to DB + reloads in-memory settings
    app_callsign = str(body.get("app_callsign", "")).strip()
    display_name = str(body.get("display_name", "RIG")).strip() or "RIG"
    default_group = str(body.get("default_group", "ALL")).strip().upper() or "ALL"

    # Manual telemetry (optional)
    def s(x: Any) -> str:
        return "" if x is None else str(x).strip()

    pairs = {
        "app_callsign": app_callsign,
        "display_name": display_name,
        "default_group": default_group,
        "manual_lat": s(body.get("manual_lat")),
        "manual_lon": s(body.get("manual_lon")),
        "manual_speed": s(body.get("manual_speed")),
        "manual_heading": s(body.get("manual_heading")),
        "manual_altitude": s(body.get("manual_altitude")),
    }
    await db_set_settings(pairs)
    await _load_settings_into_memory()

    # Optional: apply to Direwolf MYCALL
    apply_dw = bool(body.get("apply_to_direwolf", False))
    dw_result = {"applied": False, "message": "not requested"}
    if apply_dw and app_callsign:
        ok, msg = await _apply_direwolf_mycall_if_requested(app_callsign)
        dw_result = {"applied": ok, "message": msg}

    await ws_broadcast({"type": "settings_updated", "settings": _settings_public(), "secure": _secure_summary()})
    return JSONResponse({"ok": True, "settings": _settings_public(), "secure": _secure_summary(), "direwolf_apply": dw_result})


@app.post("/api/settings/secure")
async def api_settings_secure(body: dict):
    """
    Secure mode rules:
    - To ENABLE: must provide key. We store only salt + keycheck in DB; derived key stays in memory.
    - To DISABLE: clears in-memory key and sets secure_enabled=0.
    """
    global _fernet

    enable = bool(body.get("enable", False))
    key = str(body.get("key", "")).strip()

    s = await db_get_settings()
    iter_s = int((s.get("secure_kdf_iter", "200000") or "200000").strip() or "200000")

    if enable:
        if not key:
            return JSONResponse({"ok": False, "error": "Key required to enable secure mode."}, status_code=400)

        # If no salt exists, create it; else reuse existing (so same key continues to work)
        salt_b64 = (s.get("secure_salt_b64", "") or "").strip()
        if salt_b64:
            salt = _b64d(salt_b64)
        else:
            salt = os.urandom(16)
            salt_b64 = _b64e(salt)

        # Derive + compute keycheck
        f = _derive_fernet(key, salt=salt, iterations=iter_s)
        check = f.encrypt(b"NOXRADIO_KEYCHECK_V1").decode("ascii")

        await db_set_settings({
            "secure_enabled": "1",
            "secure_salt_b64": salt_b64,
            "secure_keycheck_b64": check,
        })

        # Set in-memory
        _secure["enabled"] = True
        _secure["has_key_check"] = True
        _secure["unlocked"] = True
        _fernet = f

        await db_insert_event("info", "Secure mode enabled + unlocked.")
        await ws_broadcast({"type": "secure_updated", "secure": _secure_summary()})
        return JSONResponse({"ok": True, "secure": _secure_summary()})

    # disable
    await db_set_settings({"secure_enabled": "0"})
    _secure["enabled"] = False
    _secure["unlocked"] = False
    _fernet = None

    await db_insert_event("info", "Secure mode disabled.")
    await ws_broadcast({"type": "secure_updated", "secure": _secure_summary()})
    return JSONResponse({"ok": True, "secure": _secure_summary()})


@app.post("/api/settings/unlock")
async def api_settings_unlock(body: dict):
    """
    Unlock secure mode after reboot (secure_enabled=1 but no in-memory key).
    """
    global _fernet
    key = str(body.get("key", "")).strip()
    if not key:
        return JSONResponse({"ok": False, "error": "Key required."}, status_code=400)

    s = await db_get_settings()
    if (s.get("secure_enabled", "0") != "1"):
        return JSONResponse({"ok": False, "error": "Secure mode is not enabled."}, status_code=400)

    salt_b64 = (s.get("secure_salt_b64", "") or "").strip()
    check_b64 = (s.get("secure_keycheck_b64", "") or "").strip()
    if not salt_b64 or not check_b64:
        return JSONResponse({"ok": False, "error": "No key provisioned yet. Use enable with a key first."}, status_code=400)

    iter_s = int((s.get("secure_kdf_iter", "200000") or "200000").strip() or "200000")
    salt = _b64d(salt_b64)
    f = _derive_fernet(key, salt=salt, iterations=iter_s)

    try:
        _ = f.decrypt(check_b64.encode("ascii"))
    except Exception:
        return JSONResponse({"ok": False, "error": "Key invalid."}, status_code=401)

    _secure["enabled"] = True
    _secure["has_key_check"] = True
    _secure["unlocked"] = True
    _fernet = f

    await db_insert_event("info", "Secure mode unlocked.")
    await ws_broadcast({"type": "secure_updated", "secure": _secure_summary()})
    return JSONResponse({"ok": True, "secure": _secure_summary()})


@app.post("/api/tx/beacon")
async def api_tx_beacon(body: dict):
    gid = str(body.get("group_id", _settings.get("default_group") or "ALL") or "ALL").strip().upper()
    # If provided, update manual telemetry first (so phone app can set these)
    for k in ("manual_lat", "manual_lon", "manual_speed", "manual_heading", "manual_altitude"):
        if k in body:
            try:
                _settings[k] = float(body[k]) if body[k] is not None and str(body[k]).strip() != "" else None
            except Exception:
                pass
    if "display_name" in body:
        _settings["display_name"] = str(body["display_name"]).strip() or _settings.get("display_name") or "RIG"

    payload = build_nox_beacon(gid=gid)
    await enqueue_payload_for_tx(payload)

    await db_insert_message("tx", "raw", "raw", _tx_src_callsign(), None, None, payload, None)
    await ws_broadcast({"type": "event", "level": "info", "message": "Beacon queued for TX"})
    return JSONResponse({"ok": True, "payload": payload, "secure": _secure_summary()})


@app.post("/api/tx/direct")
async def api_tx_direct(body: dict):
    to_call = str(body.get("to", "")).strip().upper()
    text = str(body.get("text", "")).rstrip()
    if not to_call or not text:
        return JSONResponse({"ok": False, "error": "to + text required"}, status_code=400)

    if _secure.get("enabled") and not _secure_can_decrypt():
        return JSONResponse({"ok": False, "error": "Secure mode enabled but not unlocked. Enter key in Settings."}, status_code=403)

    payload = build_nox_dm(to_call, text)
    await enqueue_payload_for_tx(payload)

    me = _tx_src_callsign()
    chat_id = to_call  # TX chats keyed by peer
    body_store = text
    if _secure.get("enabled"):
        # store ciphertext token so history stays decryptable after unlock
        parsed = parse_nox_payload(payload)
        if parsed and parsed["kv"].get("enc") == "1":
            body_store = "ENC:" + parsed["kv"].get("ct", "")
    await db_insert_message("tx", "direct", chat_id, me, to_call, None, body_store, None)

    await ws_broadcast({"type": "chat", "chat_type": "direct", "chat_id": chat_id, "ts": _utc_ts(),
                        "direction": "tx", "src": me, "dst": to_call, "body": text})
    return JSONResponse({"ok": True, "payload": payload, "secure": _secure_summary()})


@app.post("/api/tx/group")
async def api_tx_group(body: dict):
    gid = str(body.get("group_id", _settings.get("default_group") or "ALL") or "ALL").strip().upper()
    text = str(body.get("text", "")).rstrip()
    if not text:
        return JSONResponse({"ok": False, "error": "text required"}, status_code=400)

    if _secure.get("enabled") and not _secure_can_decrypt():
        return JSONResponse({"ok": False, "error": "Secure mode enabled but not unlocked. Enter key in Settings."}, status_code=403)

    payload = build_nox_gm(gid, text)
    await enqueue_payload_for_tx(payload)

    me = _tx_src_callsign()
    body_store = text
    if _secure.get("enabled"):
        parsed = parse_nox_payload(payload)
        if parsed and parsed["kv"].get("enc") == "1":
            body_store = "ENC:" + parsed["kv"].get("ct", "")
    await db_insert_message("tx", "group", gid, me, None, gid, body_store, None)

    await ws_broadcast({"type": "chat", "chat_type": "group", "chat_id": gid, "ts": _utc_ts(),
                        "direction": "tx", "src": me, "group_id": gid, "body": text})
    return JSONResponse({"ok": True, "payload": payload, "secure": _secure_summary()})


@app.get("/")
def index():
    return HTMLResponse(_UI_HTML)


_UI_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>NoxRadio Tactical</title>

  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

  <style>
    :root{
      --bg:#0a0f14;
      --panel:#0f1822;
      --panel2:#0c141d;
      --border:#1c2b3a;
      --text:#d7e2ee;
      --muted:#8ea2b8;
      --accent:#35ff8b;
      --accent2:#46a0ff;
      --warn:#ffcc66;
      --err:#ff5c5c;
    }
    *{ box-sizing:border-box; }
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: radial-gradient(1200px 700px at 30% 0%, #0f1a24 0%, var(--bg) 55%);
      color:var(--text);
      overflow:hidden;
    }
    .app{
      height:100vh;
      display:grid;
      grid-template-columns: 330px 1fr 440px;
      grid-template-rows: 56px 1fr 320px;
      grid-template-areas:
        "top top top"
        "left map right"
        "left map chat";
      gap:10px;
      padding:10px;
    }
    .panel{
      background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
      border:1px solid var(--border);
      border-radius:14px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.35);
      overflow:hidden;
    }
    .topbar{
      grid-area:top;
      display:flex; align-items:center; justify-content:space-between;
      padding:12px 14px;
    }
    .brand{ display:flex; align-items:center; gap:10px; }
    .logo{
      width:28px; height:28px; border-radius:9px;
      border:1px solid var(--border);
      background: linear-gradient(135deg, rgba(53,255,139,0.20), rgba(70,160,255,0.14));
      position:relative;
    }
    .logo:after{
      content:"";
      position:absolute; inset:6px;
      border:1px solid rgba(53,255,139,0.35);
      border-radius:6px;
    }
    .title{ font-weight:700; letter-spacing:0.7px; }
    .subtitle{ color:var(--muted); font-size:12px; margin-top:2px; }
    .statusRow{ display:flex; align-items:center; gap:10px; font-size:12px; color:var(--muted); }
    .pill{
      padding:6px 10px; border-radius:999px;
      border:1px solid var(--border);
      background: rgba(0,0,0,0.25);
      display:flex; align-items:center; gap:8px;
    }
    .dot{ width:8px; height:8px; border-radius:99px; background:#666; box-shadow:0 0 0 3px rgba(255,255,255,0.05) inset; }
    .dot.ok{ background: var(--accent); box-shadow: 0 0 12px rgba(53,255,139,0.25); }
    .dot.warn{ background: var(--warn); }
    .dot.err{ background: var(--err); }

    .left{ grid-area:left; display:flex; flex-direction:column; }
    .map{ grid-area:map; position:relative; }
    .right{ grid-area:right; display:flex; flex-direction:column; }
    .chat{ grid-area:chat; display:flex; flex-direction:column; }

    .sectionHead{
      padding:10px 12px;
      border-bottom:1px solid var(--border);
      display:flex; justify-content:space-between; align-items:center;
      background: rgba(0,0,0,0.22);
    }
    .sectionHead .h{ font-weight:700; letter-spacing:0.6px; font-size:12px; color:#bcd0e6; text-transform:uppercase; }
    .sectionBody{ padding:10px 12px; overflow:auto; }

    .tabs{ display:flex; gap:8px; }
    .tab{
      font-size:12px;
      padding:6px 10px;
      border-radius:10px;
      border:1px solid var(--border);
      background: rgba(0,0,0,0.20);
      cursor:pointer;
      color: var(--muted);
      user-select:none;
    }
    .tab.active{
      color: var(--text);
      border-color: rgba(53,255,139,0.35);
      box-shadow: 0 0 0 1px rgba(53,255,139,0.10) inset;
    }

    .list{ display:flex; flex-direction:column; gap:8px; }
    .item{
      padding:10px 10px;
      border:1px solid var(--border);
      border-radius:12px;
      background: rgba(0,0,0,0.18);
      cursor:pointer;
    }
    .item:hover{ border-color: rgba(53,255,139,0.35); }
    .row{ display:flex; justify-content:space-between; gap:8px; }
    .small{ font-size:12px; color:var(--muted); }
    .bold{ font-weight:700; }
    .tag{
      font-size:11px; color:#bfead0;
      border:1px solid rgba(53,255,139,0.25);
      background: rgba(53,255,139,0.08);
      padding:2px 8px; border-radius:999px;
      white-space:nowrap;
    }
    .tag.blue{
      color:#b9d9ff;
      border-color: rgba(70,160,255,0.25);
      background: rgba(70,160,255,0.10);
    }

    #map{
      position:absolute; inset:0;
      border-radius:14px;
      overflow:hidden;
      border:1px solid var(--border);
    }
    .hudOverlay{
      position:absolute; inset:0;
      pointer-events:none;
      border-radius:14px;
      background:
        linear-gradient(rgba(53,255,139,0.06) 1px, transparent 1px),
        linear-gradient(90deg, rgba(53,255,139,0.06) 1px, transparent 1px);
      background-size: 60px 60px;
      mix-blend-mode: screen;
      opacity:0.35;
    }
    .hudCorner{
      position:absolute;
      width:120px; height:120px;
      border:1px solid rgba(53,255,139,0.22);
      border-right:none; border-bottom:none;
      top:12px; left:12px;
      border-radius:14px 0 0 0;
      opacity:0.6;
    }
    .hudCorner.br{
      top:auto; left:auto; right:12px; bottom:12px;
      border-right:1px solid rgba(53,255,139,0.22);
      border-bottom:1px solid rgba(53,255,139,0.22);
      border-left:none; border-top:none;
      border-radius:0 0 14px 0;
    }

    .chatLog{
      flex:1;
      overflow:auto;
      padding:10px 12px;
      display:flex;
      flex-direction:column;
      gap:10px;
    }
    .bubble{
      max-width: 94%;
      padding:10px 12px;
      border-radius:14px;
      border:1px solid var(--border);
      background: rgba(0,0,0,0.25);
      white-space: pre-wrap;
    }
    .bubble.me{
      margin-left:auto;
      border-color: rgba(70,160,255,0.35);
      background: rgba(70,160,255,0.10);
    }
    .bubble .meta{
      display:flex; justify-content:space-between; gap:8px;
      font-size:11px; color:var(--muted);
      margin-bottom:4px;
    }

    .composer{
      padding:10px 12px;
      border-top:1px solid var(--border);
      background: rgba(0,0,0,0.22);
      display:flex;
      flex-direction:column;
      gap:8px;
    }
    .composerTop{
      display:flex; gap:8px; align-items:center;
    }
    .composerBottom{
      display:flex; gap:8px; align-items:flex-end;
    }

    input, select, textarea{
      width:100%;
      padding:10px 10px;
      border-radius:12px;
      border:1px solid var(--border);
      background: rgba(0,0,0,0.25);
      color: var(--text);
      outline:none;
    }
    textarea{
      resize:none;
      min-height:44px;
      max-height:140px;
      overflow:auto;
      line-height:1.25;
    }
    button{
      padding:10px 12px;
      border-radius:12px;
      border:1px solid rgba(53,255,139,0.30);
      background: rgba(53,255,139,0.10);
      color: var(--text);
      cursor:pointer;
      white-space:nowrap;
      font-weight:700;
      letter-spacing:0.3px;
    }
    button:hover{ background: rgba(53,255,139,0.16); }
    .btnBlue{
      border-color: rgba(70,160,255,0.35);
      background: rgba(70,160,255,0.12);
    }
    .btnBlue:hover{ background: rgba(70,160,255,0.18); }
    .btnWarn{
      border-color: rgba(255,204,102,0.35);
      background: rgba(255,204,102,0.10);
    }
    .btnWarn:hover{ background: rgba(255,204,102,0.16); }

    .kv{ display:grid; grid-template-columns: 1fr 1fr; gap:8px; }
    .mini{ font-size:11px; color: var(--muted); }

    .leaflet-control-attribution{ display:none; }
    .leaflet-control-zoom a{
      background: rgba(0,0,0,0.45) !important;
      color: var(--text) !important;
      border:1px solid var(--border) !important;
    }
  </style>
</head>
<body>
  <div class="app">
    <div class="panel topbar">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <div class="title">NOXRADIO</div>
          <div class="subtitle">Tactical RF Data Link • Web UI + REST API</div>
        </div>
      </div>
      <div class="statusRow">
        <div class="pill"><span id="dwDot" class="dot"></span><span id="dwText">Direwolf: …</span></div>
        <div class="pill"><span id="secDot" class="dot"></span><span id="secText">Secure: …</span></div>
      </div>
    </div>

    <!-- LEFT -->
    <div class="panel left">
      <div class="sectionHead">
        <div class="h">Control</div>
        <div class="tabs">
          <div class="tab active" id="tabRoster" onclick="setLeftTab('roster')">Roster</div>
          <div class="tab" id="tabAdmin" onclick="setLeftTab('admin')">Groups</div>
          <div class="tab" id="tabSettings" onclick="setLeftTab('settings')">Settings</div>
        </div>
      </div>
      <div class="sectionBody" id="leftBody"></div>
    </div>

    <!-- MAP -->
    <div class="map">
      <div id="map"></div>
      <div class="hudOverlay"></div>
      <div class="hudCorner"></div>
      <div class="hudCorner br"></div>
    </div>

    <!-- RIGHT -->
    <div class="panel right">
      <div class="sectionHead">
        <div class="h">Signals</div>
        <div class="tabs">
          <div class="tab active" id="tabSignals" onclick="setRightTab('signals')">RX</div>
          <div class="tab" id="tabEvents" onclick="setRightTab('events')">Events</div>
        </div>
      </div>
      <div class="sectionBody" id="rightBody"></div>
    </div>

    <!-- CHAT -->
    <div class="panel chat">
      <div class="sectionHead">
        <div class="h">Comms</div>
        <div class="tabs">
          <div class="tab active" id="tabGroup" onclick="setChatMode('group')">Group</div>
          <div class="tab" id="tabDirect" onclick="setChatMode('direct')">Direct</div>
        </div>
      </div>

      <div class="chatLog" id="chatLog"></div>

      <div class="composer">
        <div class="composerTop">
          <div style="flex: 0 0 200px;">
            <select id="chatTarget"></select>
            <div class="mini" id="chatHint">Group channel</div>
          </div>
          <button class="btnBlue" onclick="sendQuickBeacon()">Beacon</button>
        </div>

        <div class="composerBottom">
          <textarea id="chatText" placeholder="Type message… (Shift+Enter = newline)"></textarea>
          <button onclick="sendChat()">Send</button>
        </div>

        <div class="mini" id="composerNote"></div>
      </div>
    </div>
  </div>

<script>
  let leftTab = "roster";
  let rightTab = "signals";
  let chatMode = "group";

  const groups = new Map();
  const nodes = new Map();
  const markers = new Map();

  let map = null;
  let ws = null;

  let secure = { enabled:false, has_key_check:false, unlocked:false };
  let settings = { app_callsign:"", display_name:"RIG", default_group:"ALL", manual_lat:null, manual_lon:null, manual_speed:null, manual_heading:null, manual_altitude:null };

  const $ = (id) => document.getElementById(id);
  function safe(s){ return (s ?? "").toString(); }
  function fmtAge(ts){
    if(!ts) return "—";
    const s = Math.max(0, Math.floor(Date.now()/1000 - ts));
    if(s < 60) return s+"s";
    const m = Math.floor(s/60);
    if(m < 60) return m+"m";
    const h = Math.floor(m/60);
    return h+"h";
  }

  function initMap(){
    if(!window.L){
      console.warn("Leaflet failed to load.");
      return;
    }
    map = L.map("map", { zoomControl:true }).setView([40.0, -98.0], 4);
    const tiles = L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", { maxZoom: 19 });
    tiles.addTo(map);
  }

  function upsertMarker(node){
    if(!map || !window.L) return;
    if(node.lat == null || node.lon == null) return;

    const key = node.node_id;
    const label = (node.name ? node.name + " • " : "") + node.callsign;
    const sub = (node.group_id ? "Group: "+node.group_id+" • " : "") + "Seen: " + fmtAge(node.last_seen_ts);

    const html = `<div style="color:#d7e2ee">
      <div style="font-weight:800; letter-spacing:0.4px">${label}</div>
      <div style="color:#8ea2b8; font-size:12px; margin-top:2px">${sub}</div>
      <div style="color:#8ea2b8; font-size:12px; margin-top:6px">
        ${node.lat.toFixed(5)}, ${node.lon.toFixed(5)}
      </div>
    </div>`;

    let mk = markers.get(key);
    if(!mk){
      mk = L.marker([node.lat, node.lon], { title: label });
      mk.addTo(map);
      mk.bindPopup(html);
      mk.on("click", () => focusDirectChat(node.callsign));
      markers.set(key, mk);
    } else {
      mk.setLatLng([node.lat, node.lon]);
      mk.setPopupContent(html);
    }
  }

  function setLeftTab(t){
    leftTab = t;
    $("tabRoster").classList.toggle("active", t==="roster");
    $("tabAdmin").classList.toggle("active", t==="admin");
    $("tabSettings").classList.toggle("active", t==="settings");
    renderLeft();
  }

  function setRightTab(t){
    rightTab = t;
    $("tabSignals").classList.toggle("active", t==="signals");
    $("tabEvents").classList.toggle("active", t==="events");
    renderRight();
  }

  function setChatMode(t){
    chatMode = t;
    $("tabGroup").classList.toggle("active", t==="group");
    $("tabDirect").classList.toggle("active", t==="direct");
    $("chatHint").textContent = (t==="group") ? "Group channel" : "Direct to callsign";
    renderChatTarget();
    loadChatHistory();
  }

  function renderLeft(){
    const el = $("leftBody");

    if(leftTab === "admin"){
      el.innerHTML = `
        <div class="kv">
          <div>
            <div class="small">Create/Update Group</div>
            <input id="newGid" placeholder="GROUP ID (e.g. ALPHA)" />
          </div>
          <div>
            <div class="small">&nbsp;</div>
            <input id="newGname" placeholder="Name (optional)" />
          </div>
        </div>
        <div style="margin-top:10px; display:flex; gap:8px;">
          <button onclick="createGroup()">Save Group</button>
          <button class="btnBlue" onclick="refreshAll()">Refresh</button>
        </div>
        <div style="margin-top:14px;" class="mini">
          Tip: Only NOXRADIO payload nodes populate roster (NR1|...). APRS is still visible in RX.
        </div>
      `;
      return;
    }

    if(leftTab === "settings"){
      const secState = secure.enabled ? (secure.unlocked ? "ENABLED (UNLOCKED)" : "ENABLED (LOCKED)") : "DISABLED";
      const secColor = secure.enabled ? (secure.unlocked ? "tag" : "tag blue") : "tag blue";

      el.innerHTML = `
        <div class="item" style="cursor:default">
          <div class="row">
            <div class="bold">Rig Settings</div>
            <div class="${secColor}">${secState}</div>
          </div>
          <div class="small" style="margin-top:6px">
            App callsign overrides TX source. Optional: apply to Direwolf MYCALL (requires safe chars).
          </div>
        </div>

        <div class="kv" style="margin-top:10px">
          <div>
            <div class="small">App Callsign (TX source)</div>
            <input id="setCall" value="${safe(settings.app_callsign)}" placeholder="e.g. N0CALL-10" />
          </div>
          <div>
            <div class="small">Display Name</div>
            <input id="setName" value="${safe(settings.display_name)}" placeholder="RIG" />
          </div>
        </div>

        <div class="kv" style="margin-top:8px">
          <div>
            <div class="small">Default Group</div>
            <input id="setGroup" value="${safe(settings.default_group)}" placeholder="ALL" />
          </div>
          <div>
            <div class="small">Apply to Direwolf MYCALL</div>
            <select id="applyDw">
              <option value="0">No</option>
              <option value="1">Yes</option>
            </select>
          </div>
        </div>

        <div class="small" style="margin-top:14px">Manual Telemetry (used for “Beacon” button / testing)</div>
        <div class="kv" style="margin-top:8px">
          <div><input id="setLat"  value="${safe(settings.manual_lat)}" placeholder="Latitude" /></div>
          <div><input id="setLon"  value="${safe(settings.manual_lon)}" placeholder="Longitude" /></div>
        </div>
        <div class="kv" style="margin-top:8px">
          <div><input id="setSpd"  value="${safe(settings.manual_speed)}" placeholder="Speed (optional)" /></div>
          <div><input id="setHdg"  value="${safe(settings.manual_heading)}" placeholder="Heading (optional)" /></div>
        </div>
        <div class="kv" style="margin-top:8px">
          <div><input id="setAlt"  value="${safe(settings.manual_altitude)}" placeholder="Altitude (optional)" /></div>
          <div></div>
        </div>

        <div style="margin-top:10px; display:flex; gap:8px;">
          <button onclick="saveSettings()">Save</button>
          <button class="btnBlue" onclick="refreshAll()">Reload</button>
        </div>

        <div class="item" style="margin-top:14px; cursor:default">
          <div class="row">
            <div class="bold">Secure Mode</div>
            <div class="tag">AES (Fernet)</div>
          </div>
          <div class="small" style="margin-top:6px">
            When enabled, messages + beacons encrypt/decrypt with your key.
            Key is never stored in the browser. After reboot you must unlock again.
          </div>

          <div style="margin-top:10px">
            <div class="small">Key</div>
            <input id="secKey" type="password" placeholder="Enter key / passphrase" />
          </div>

          <div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
            <button class="btnWarn" onclick="enableSecure()">Enable Secure (set key)</button>
            <button class="btnBlue" onclick="unlockSecure()">Unlock</button>
            <button onclick="disableSecure()">Disable Secure</button>
          </div>

          <div class="mini" id="secMsg" style="margin-top:10px"></div>
        </div>
      `;
      $("applyDw").value = "0";
      return;
    }

    // roster view
    const grpList = Array.from(groups.values()).sort((a,b)=>a.group_id.localeCompare(b.group_id));
    const nodeList = Array.from(nodes.values()).sort((a,b)=>(b.last_seen_ts||0)-(a.last_seen_ts||0));

    const grpHtml = grpList.map(g=>{
      return `<div class="item" onclick="selectGroup('${g.group_id}')">
        <div class="row">
          <div class="bold">${g.group_id}</div>
          <div class="tag">${safe(g.name||g.group_id)}</div>
        </div>
        <div class="small">Tap to focus group chat</div>
      </div>`;
    }).join("");

    const nodeHtml = nodeList.slice(0, 30).map(n=>{
      const name = n.name ? `${safe(n.name)} • ` : "";
      const g = n.group_id ? n.group_id : "—";
      return `<div class="item" onclick="focusDirectChat('${safe(n.callsign)}')">
        <div class="row">
          <div class="bold">${name}${safe(n.callsign)}</div>
          <div class="tag blue">${g}</div>
        </div>
        <div class="small">Seen ${fmtAge(n.last_seen_ts)} • ${n.lat!=null? n.lat.toFixed(4)+", "+n.lon.toFixed(4) : "No GPS"}</div>
      </div>`;
    }).join("");

    el.innerHTML = `
      <div class="small" style="margin-bottom:8px;">Groups</div>
      <div class="list">${grpHtml}</div>
      <div class="small" style="margin:14px 0 8px;">Roster (NOXRADIO nodes)</div>
      <div class="list">${nodeHtml || '<div class="small">No NOXRADIO nodes yet.</div>'}</div>
    `;
  }

  function renderRight(){
    const el = $("rightBody");
    if(rightTab === "events"){
      el.innerHTML = `<div class="small">Events stream appears in real-time. Use systemd logs for full history.</div>
        <div id="eventsList" class="list" style="margin-top:10px;"></div>`;
      return;
    }
    el.innerHTML = `<div class="small">Raw RX (TNC2) – APRS + NOXRADIO (monitor everything).</div>
      <div id="rxList" class="list" style="margin-top:10px;"></div>`;
  }

  function renderChatTarget(){
    const sel = $("chatTarget");
    sel.innerHTML = "";
    if(chatMode === "group"){
      const list = Array.from(groups.values()).sort((a,b)=>a.group_id.localeCompare(b.group_id));
      for(const g of list){
        const opt = document.createElement("option");
        opt.value = g.group_id;
        opt.textContent = `${g.group_id}`;
        sel.appendChild(opt);
      }
      sel.value = sel.value || settings.default_group || "ALL";
    } else {
      const list = Array.from(nodes.values()).sort((a,b)=>(b.last_seen_ts||0)-(a.last_seen_ts||0));
      for(const n of list){
        const opt = document.createElement("option");
        opt.value = n.callsign;
        opt.textContent = n.name ? `${n.name} • ${n.callsign}` : n.callsign;
        sel.appendChild(opt);
      }
      if(sel.options.length === 0){
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "(no nodes yet)";
        sel.appendChild(opt);
      }
    }
  }

  function addBubble(msg){
    const log = $("chatLog");
    const div = document.createElement("div");
    div.className = "bubble" + (msg.direction === "tx" ? " me" : "");
    const who = msg.chat_type === "group" ? `${safe(msg.src)} → ${safe(msg.group_id)}` : `${safe(msg.src)} → ${safe(msg.dst||msg.chat_id)}`;
    const when = new Date((msg.ts||Math.floor(Date.now()/1000))*1000).toLocaleTimeString();
    div.innerHTML = `<div class="meta"><span>${who}</span><span>${when}</span></div><div>${safe(msg.body)}</div>`;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  async function loadChatHistory(){
    $("chatLog").innerHTML = "";
    const tgt = $("chatTarget").value;
    if(!tgt) return;
    const url = `/api/messages?chat_type=${encodeURIComponent(chatMode)}&chat_id=${encodeURIComponent(tgt)}&limit=160`;
    const res = await fetch(url);
    const data = await res.json();
    (data.messages || []).forEach(addBubble);
  }

  function selectGroup(gid){
    setChatMode("group");
    $("chatTarget").value = gid;
    loadChatHistory();
  }

  function focusDirectChat(callsign){
    setChatMode("direct");
    renderChatTarget();
    $("chatTarget").value = callsign;
    loadChatHistory();
  }

  async function createGroup(){
    const gid = ($("newGid")?.value || "").trim().toUpperCase();
    const name = ($("newGname")?.value || "").trim();
    if(!gid) return;
    await fetch("/api/groups", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ group_id: gid, name })});
    await refreshAll();
    $("newGid").value = "";
    $("newGname").value = "";
  }

  function setDwStatus(dw){
    const dot = $("dwDot");
    const txt = $("dwText");
    const state = (dw?.state || "unknown");
    dot.className = "dot";
    if(state === "connected") dot.classList.add("ok");
    else if(state === "connecting") dot.classList.add("warn");
    else dot.classList.add("err");
    txt.textContent = `Direwolf: ${state} (${dw?.host || "?"}:${dw?.port || "?"})`;
  }

  function setSecureStatus(sec){
    secure = sec || secure;
    const dot = $("secDot");
    const txt = $("secText");
    dot.className = "dot";
    if(!secure.enabled){
      dot.classList.add("warn");
      txt.textContent = "Secure: OFF";
      $("composerNote").textContent = "Open mode: messages are plaintext.";
      return;
    }
    if(secure.unlocked){
      dot.classList.add("ok");
      txt.textContent = "Secure: ON (unlocked)";
      $("composerNote").textContent = "Secure mode: messages + beacons are encrypted.";
    } else {
      dot.classList.add("err");
      txt.textContent = "Secure: ON (locked)";
      $("composerNote").textContent = "Secure mode is locked. Go to Settings and enter the key to unlock.";
    }
  }

  function applyBootstrap(data){
    setDwStatus(data.dw);
    setSecureStatus(data.secure);
    settings = data.settings || settings;

    groups.clear();
    (data.groups || []).forEach(g => groups.set(g.group_id, g));

    nodes.clear();
    (data.nodes || []).forEach(n => nodes.set(n.node_id, n));

    renderLeft();
    renderRight();
    renderChatTarget();

    for(const n of nodes.values()){
      upsertMarker(n);
    }
  }

  function addRightItem(kind, title, sub){
    if(rightTab === "signals" && kind !== "rx") return;
    if(rightTab === "events" && kind !== "event") return;

    const list = (kind === "rx") ? $("rxList") : $("eventsList");
    if(!list) return;

    const div = document.createElement("div");
    div.className = "item";
    div.innerHTML = `<div class="row"><div class="bold">${safe(title)}</div><div class="small">${safe(sub)}</div></div>`;
    list.prepend(div);
    while(list.children.length > 80) list.removeChild(list.lastChild);
  }

  async function connectWs(){
    if(ws) try{ ws.close(); }catch(e){}
    ws = new WebSocket(`ws://${location.host}/ws`);
    ws.onopen = () => addRightItem("event", "WebSocket connected", "");
    ws.onclose = () => addRightItem("event", "WebSocket closed", "");
    ws.onerror = () => addRightItem("event", "WebSocket error", "");

    ws.onmessage = (ev) => {
      let msg = null;
      try{ msg = JSON.parse(ev.data); }catch(e){ return; }

      if(msg.type === "status"){
        setDwStatus(msg.dw);
        if(msg.secure) setSecureStatus(msg.secure);
        if(msg.settings) settings = msg.settings;
        return;
      }

      if(msg.type === "event"){
        addRightItem("event", msg.message, msg.level || "");
        return;
      }

      if(msg.type === "rx"){
        addRightItem("rx", msg.src + "  " + (msg.payload||""), "TNC2");
        return;
      }

      if(msg.type === "beacon"){
        const n = msg.node || {};
        const existing = nodes.get(n.node_id) || {};
        const merged = { ...existing, ...n, last_seen_ts: Math.floor(Date.now()/1000) };
        nodes.set(n.node_id, merged);
        upsertMarker(merged);
        renderLeft();
        return;
      }

      if(msg.type === "chat"){
        const target = $("chatTarget").value;
        if(msg.chat_type === chatMode && msg.chat_id === target){
          addBubble(msg);
        }
        addRightItem("event", `Chat ${msg.chat_type.toUpperCase()} ${msg.chat_id}`, msg.direction);
        return;
      }

      if(msg.type === "groups_updated" || msg.type === "settings_updated" || msg.type === "secure_updated"){
        refreshAll();
        return;
      }
    };
  }

  async function refreshAll(){
    const res = await fetch("/api/bootstrap");
    const data = await res.json();
    applyBootstrap(data);
  }

  async function sendChat(){
    const text = ($("chatText").value || "").trimEnd();
    if(!text) return;

    if(secure.enabled && !secure.unlocked){
      addRightItem("event", "Secure is locked. Enter key in Settings.", "warn");
      return;
    }

    const target = $("chatTarget").value;

    if(chatMode === "group"){
      await fetch("/api/tx/group", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ group_id: target, text })});
    } else {
      await fetch("/api/tx/direct", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ to: target, text })});
    }
    $("chatText").value = "";
    autoGrow($("chatText"));
  }

  async function sendQuickBeacon(){
    if(secure.enabled && !secure.unlocked){
      addRightItem("event", "Secure is locked. Enter key in Settings.", "warn");
      return;
    }
    const gid = (chatMode === "group" ? $("chatTarget").value : (settings.default_group || "ALL")) || "ALL";
    await fetch("/api/tx/beacon", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({
        group_id: gid,
        display_name: settings.display_name,
        manual_lat: settings.manual_lat,
        manual_lon: settings.manual_lon,
        manual_speed: settings.manual_speed,
        manual_heading: settings.manual_heading,
        manual_altitude: settings.manual_altitude
      })
    });
  }

  async function saveSettings(){
    const payload = {
      app_callsign: ($("setCall").value || "").trim(),
      display_name: ($("setName").value || "RIG").trim(),
      default_group: ($("setGroup").value || "ALL").trim(),
      manual_lat: ($("setLat").value || "").trim(),
      manual_lon: ($("setLon").value || "").trim(),
      manual_speed: ($("setSpd").value || "").trim(),
      manual_heading: ($("setHdg").value || "").trim(),
      manual_altitude: ($("setAlt").value || "").trim(),
      apply_to_direwolf: ($("applyDw").value === "1")
    };
    const res = await fetch("/api/settings", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify(payload) });
    const data = await res.json();
    if(data?.direwolf_apply?.message){
      addRightItem("event", data.direwolf_apply.message, data.direwolf_apply.applied ? "info" : "warn");
    }
    await refreshAll();
  }

  async function enableSecure(){
    const key = ($("secKey").value || "").trim();
    const msg = $("secMsg");
    msg.textContent = "";
    const res = await fetch("/api/settings/secure", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ enable:true, key })});
    const data = await res.json();
    if(!data.ok){
      msg.textContent = data.error || "Failed";
      return;
    }
    $("secKey").value = "";
    msg.textContent = "Secure enabled + unlocked.";
    await refreshAll();
  }

  async function unlockSecure(){
    const key = ($("secKey").value || "").trim();
    const msg = $("secMsg");
    msg.textContent = "";
    const res = await fetch("/api/settings/unlock", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ key })});
    const data = await res.json();
    if(!data.ok){
      msg.textContent = data.error || "Failed";
      return;
    }
    $("secKey").value = "";
    msg.textContent = "Unlocked.";
    await refreshAll();
  }

  async function disableSecure(){
    const msg = $("secMsg");
    msg.textContent = "";
    const res = await fetch("/api/settings/secure", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ enable:false })});
    const data = await res.json();
    if(!data.ok){
      msg.textContent = data.error || "Failed";
      return;
    }
    msg.textContent = "Secure disabled.";
    await refreshAll();
  }

  function autoGrow(el){
    if(!el) return;
    el.style.height = "auto";
    const h = Math.min(140, Math.max(44, el.scrollHeight));
    el.style.height = h + "px";
  }

  (async function init(){
    initMap();
    await refreshAll();
    await connectWs();
    setTimeout(loadChatHistory, 250);

    $("chatTarget").addEventListener("change", loadChatHistory);

    const ta = $("chatText");
    ta.addEventListener("input", () => autoGrow(ta));
    autoGrow(ta);

    ta.addEventListener("keydown", (e) => {
      if(e.key === "Enter" && !e.shiftKey){
        e.preventDefault();
        sendChat();
      }
    });
  })();
</script>
</body>
</html>
"""


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    global _reader_task
    await ws.accept()
    clients.add(ws)

    if _reader_task is None or _reader_task.done():
        _reader_task = asyncio.create_task(direwolf_reader())

    await ws.send_text(json.dumps({
        "type": "status",
        "dw": dw_status,
        "secure": _secure_summary(),
        "settings": _settings_public(),
    }, separators=(",", ":")))

    try:
        while True:
            # REST-first UI; WS is push-only for now.
            await ws.receive_text()
    except WebSocketDisconnect:
        clients.discard(ws)
PY

  log "Wrote web app: ${WEB_DIR}/app.py"
}

write_web_service() {
  local svc="/etc/systemd/system/noxradio-web.service"
  local PY="/usr/bin/python3"
  [[ -x "${PY}" ]] || die "python3 not found at ${PY}"

  cat > "${svc}" <<EOF
[Unit]
Description=NoxRadio Tactical Web + REST API
After=network.target direwolf.service
Wants=direwolf.service

[Service]
Type=simple
User=${NOXRADIO_USER}
WorkingDirectory=${WEB_DIR}
Environment=NOXRADIO_DB_PATH=${DB_PATH}
Environment=NOXRADIO_CACHE_MAX_EVENTS=${CACHE_MAX_EVENTS}
Environment=DIREWOLF_KISS_HOST=127.0.0.1
Environment=DIREWOLF_KISS_PORT=${KISS_PORT}
ExecStart=${PY} -m uvicorn app:app --host 0.0.0.0 --port ${WEB_PORT}
Restart=on-failure
RestartSec=2
KillMode=control-group
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now noxradio-web
  log "Enabled + started noxradio-web.service"
}

verify_services() {
  log "Service status:"
  systemctl --no-pager --full status direwolf || true
  systemctl --no-pager --full status noxradio-web || true
  systemctl --no-pager --full status noxradio-ax25-bridge || true

  log "Listening ports:"
  ss -ltnp | grep -E ":(${KISS_PORT}|${WEB_PORT})" || true

  log "DB location:"
  echo "  ${DB_PATH}"
}

main() {
  is_root || die "Run as root: sudo $0"

  # Fresh OS assumption: install dependencies before requiring them.
  need_cmd apt-get

  local primary_user
  primary_user="$(detect_primary_user)"
  log "Primary user: ${primary_user}"

  cat >&2 <<EOF

============================================================
  NoxRadio - Installer
============================================================

This installer will set up:
- Direwolf (built from source)
- AX.25 tools/modules (ax25-tools, ax25-apps, libax25)
- KISS TCP interface (default 127.0.0.1:${KISS_PORT})
- NoxRadio web UI + API backend (FastAPI/Uvicorn)
- systemd services: direwolf + noxradio-web

Web UI will listen on: http://<device-ip>:${WEB_PORT}

EOF

  if [[ -t 0 ]]; then
    read -r -n 1 -s -p "Press any key to start installation..." || true
    echo "" >&2
  fi

  log "Updating OS packages..."
  apt-get update -y
  apt-get full-upgrade -y

  # Core deps + AX.25 tooling + python runtime + tools used by this script
  apt_install ca-certificates udev git iproute2 \
    build-essential cmake pkg-config \
    libasound2-dev libudev-dev alsa-utils socat \
    python3 sqlite3 \
    ax25-tools ax25-apps libax25 || true

  # Now that deps are installed, verify commands we rely on.
  need_cmd udevadm
  need_cmd git

  need_cmd arecord
  need_cmd aplay

  install_web_deps_apt_only

  ensure_noxradio_user
  setup_storage_dirs

  log "Detecting AIOC devices (audio + PTT)..."
  local audio_card hid_node tty_node
  audio_card="$(detect_audio_capture_card)"
  hid_node="$(detect_ptt_hidraw_device)"
  tty_node="$(detect_serial_tty_device)"

  [[ -n "${audio_card}" ]] && log "Detected USB capture card index: ${audio_card}" || warn "No USB capture device detected yet. Plug in the AIOC and re-run this script."
  [[ -n "${hid_node}" ]] && log "Detected hidraw device for PTT: ${hid_node}" || warn "No /dev/hidraw* detected (CM108 PTT). Will try serial PTT if available."
  [[ -n "${tty_node}" ]] && log "Detected serial device: ${tty_node}" || warn "No /dev/ttyACM0 or /dev/ttyUSB0 detected."

  ensure_direwolf_user

  if [[ -n "${hid_node}" || -n "${tty_node}" ]]; then
    write_udev_rules "${hid_node}" "${tty_node}"
  else
    warn "Skipping udev rules (no hidraw/tty detected)."
  fi

  install_direwolf

  local mycall
  mycall="$(prompt_callsign)"
  mycall="$(echo -n "${mycall}" | tr -d ' \t\r\n')"
  [[ -n "${mycall}" ]] || mycall="N0CALL-10"
  log "Using MYCALL: ${mycall}"

  write_direwolf_config "${audio_card}" "${hid_node}" "${tty_node}" "${mycall}"
  write_direwolf_service

  write_modules_load
  write_axports "${mycall}"

  if command -v kissattach >/dev/null 2>&1; then
    write_ax25_bridge_script
    write_ax25_bridge_service
  else
    warn "Skipping AX.25 bridge service (kissattach missing)."
  fi

  write_direwolf_mycall_helper
  write_web_app
  chown -R "${NOXRADIO_USER}:${NOXRADIO_USER}" "${WEB_DIR}"
  write_web_service

  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"

  echo ""
  echo "============================================================"
  echo " Install complete"
  echo "============================================================"
  echo "Direwolf config: ${DW_CONF}"
  echo "Web UI:         http://${ip:-<pi-ip>}:${WEB_PORT}"
  echo "Health:         http://${ip:-<pi-ip>}:${WEB_PORT}/health"
  echo "Bootstrap:      http://${ip:-<pi-ip>}:${WEB_PORT}/api/bootstrap"
  echo "KISS TCP:       127.0.0.1:${KISS_PORT}"
  echo "DB:             ${DB_PATH}"
  echo ""
  echo "Service logs:"
  echo "  sudo journalctl -u direwolf -n 120 --no-pager"
  echo "  sudo journalctl -u noxradio-web -n 120 --no-pager"
  echo ""

  verify_services
}

main "$@"
