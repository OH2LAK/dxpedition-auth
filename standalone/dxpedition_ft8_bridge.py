#!/usr/bin/env python3
"""
FT8 / WSJT-X Authentication Bridge  (standalone / .exe version)
================================================================

Reads configuration from  dxpedition_config.json  next to this file.

Runs alongside WSJT-X on the DXpedition operating computer.

  1. Every time the 5-minute auth code changes, this script automatically
     updates the WSJT-X free text field to  "AUTH XXXX".
  2. Monitors decoded FT8 messages from WSJT-X and logs contacts where
     a calling station's auth code appears in their transmission.

REQUIREMENTS:
  WSJT-X Settings -> Reporting -> UDP Server enabled on 127.0.0.1:2237

USAGE:
  ft8_bridge.exe
  ft8_bridge.exe --host 127.0.0.1 --port 2237
"""

import argparse, json, os, sys, hmac as _hmac, hashlib, socket, struct, time
from datetime import datetime, timezone

# ─── Config loading ──────────────────────────────────────────────────────────

def _base_dir():
    """Directory containing this script or frozen .exe."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def load_config():
    path = os.path.join(_base_dir(), "dxpedition_config.json")
    if not os.path.exists(path):
        print(f"\n  ERROR: Config file not found:\n  {path}")
        print("\n  Run generate_tools.py first to create dxpedition_config.json,")
        print("  then place it next to this executable.\n")
        input("  Press Enter to exit...")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    for field in ("callsign", "key"):
        if field not in cfg:
            print(f"\n  ERROR: Missing '{field}' in dxpedition_config.json\n")
            input("  Press Enter to exit...")
            sys.exit(1)
    return cfg

CFG         = load_config()
DXPED       = CFG["callsign"].upper()
SECRET_KEY  = CFG["key"]
WINDOW_SECS = CFG.get("window_seconds", 300)

# ─── WSJT-X UDP protocol constants ──────────────────────────────────────────

WSJTX_MAGIC  = 0xADBCCBDA
WSJTX_SCHEMA = 2
MSG_FREE_TEXT = 9
MSG_DECODE    = 2
MSG_STATUS    = 1

# ─── Crypto: DLLL format ────────────────────────────────────────────────────

DIGIT_ALPHA  = "234567"
LETTER_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def _auth_code(message):
    key = bytes.fromhex(SECRET_KEY)
    d = _hmac.new(key, message.encode(), hashlib.sha256).digest()
    return (DIGIT_ALPHA[d[0]%6] + LETTER_ALPHA[d[1]%26] +
            LETTER_ALPHA[d[2]%26] + LETTER_ALPHA[d[3]%26])

def current_code(window=None):
    if window is None: window = int(time.time() // WINDOW_SECS)
    return _auth_code(f"DXPED:{DXPED}:{window}")

def expected_station_code(call):
    return _auth_code(f"STATION:{call.upper().strip()}:{DXPED}")

# ─── Qt QDataStream packing ─────────────────────────────────────────────────

def _qstring(s):
    if s is None: return struct.pack(">I", 0xFFFFFFFF)
    b = s.encode("utf-16-be")
    return struct.pack(">I", len(b)) + b

def _qbytearray(b):
    if b is None: return struct.pack(">I", 0xFFFFFFFF)
    return struct.pack(">I", len(b)) + b

def _unpack_qstring(data, offset):
    length = struct.unpack_from(">I", data, offset)[0]; offset += 4
    if length == 0xFFFFFFFF: return None, offset
    s = data[offset:offset+length].decode("utf-16-be", errors="replace")
    return s, offset + length

def _unpack_qbytearray(data, offset):
    length = struct.unpack_from(">I", data, offset)[0]; offset += 4
    if length == 0xFFFFFFFF: return None, offset
    return data[offset:offset+length], offset + length

# ─── WSJT-X message builders ────────────────────────────────────────────────

def build_free_text_packet(text, client_id="DXAuth", send_now=False):
    hdr  = struct.pack(">III", WSJTX_MAGIC, WSJTX_SCHEMA, MSG_FREE_TEXT)
    hdr += _qbytearray(client_id.encode("utf-8"))
    body = _qstring(text) + struct.pack("?", send_now)
    return hdr + body

def parse_decode(data):
    try:
        magic, schema, msg_type = struct.unpack_from(">III", data, 0)
        if magic != WSJTX_MAGIC or msg_type != MSG_DECODE: return None
        offset = 12
        _, offset     = _unpack_qbytearray(data, offset)
        new_decode    = struct.unpack_from("?", data, offset)[0]; offset += 1
        utc_ms        = struct.unpack_from(">I", data, offset)[0]; offset += 4
        snr           = struct.unpack_from(">i", data, offset)[0]; offset += 4
        delta_t       = struct.unpack_from(">d", data, offset)[0]; offset += 8
        delta_f       = struct.unpack_from(">I", data, offset)[0]; offset += 4
        mode,  offset = _unpack_qstring(data, offset)
        msg,   offset = _unpack_qstring(data, offset)
        return {"new": new_decode, "snr": snr, "mode": mode, "message": msg or ""}
    except Exception:
        return None

# ─── Main bridge logic ──────────────────────────────────────────────────────

G="\033[92m"; D="\033[2m"; Y="\033[93m"; C="\033[96m"; R="\033[91m"; RST="\033[0m"

def ts(): return datetime.now(timezone.utc).strftime("%H:%M:%S")

def run(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)

    last_win  = -1
    last_code = ""

    print(f"\n  {G}FT8 Authentication Bridge  ·  {DXPED}{RST}")
    print(f"  {D}Listening on {host}:{port}  |  WSJT-X must have UDP enabled{RST}")
    print(f"  {D}{'─'*56}{RST}\n")

    def push_code(code):
        text   = f"AUTH {code}"
        packet = build_free_text_packet(text)
        try:
            sock.sendto(packet, ("127.0.0.1", port))
            print(f"  {ts()}  {G}▶ Set WSJT-X free text →  {text}{RST}")
        except Exception as e:
            print(f"  {ts()}  {R}✗ Could not reach WSJT-X: {e}{RST}")

    try:
        while True:
            win  = int(time.time() // WINDOW_SECS)
            code = current_code(win)
            if win != last_win:
                last_win, last_code = win, code
                remain = WINDOW_SECS - (time.time() % WINDOW_SECS)
                print(f"  {ts()}  {Y}New 5-min window  →  code: {G}{code}  "
                      f"{D}(valid {int(remain//60):02d}:{int(remain%60):02d}){RST}")
                push_code(code)

            try:
                data, _ = sock.recvfrom(4096)
                dec = parse_decode(data)
                if dec and dec["new"] and dec["message"]:
                    msg = dec["message"].upper()
                    if f"AUTH {code}" in msg:
                        print(f"  {ts()}  {C}✓ Received own auth code in decode: {dec['message']}{RST}")
                    words = msg.split()
                    if len(words) >= 2 and len(words[-1]) == 4:
                        call = words[0]
                        rcvd = words[-1]
                        exp  = expected_station_code(call)
                        if rcvd == exp:
                            print(f"  {ts()}  {G}✓ Station code match: {call}  code: {rcvd}{RST}")
            except socket.timeout:
                pass

    except KeyboardInterrupt:
        print(f"\n  {D}73 de {DXPED}{RST}\n")
    finally:
        sock.close()

def main():
    ap = argparse.ArgumentParser(description="FT8 Auth Bridge for " + DXPED)
    ap.add_argument("--host", default="0.0.0.0", help="UDP bind address (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=2237, help="WSJT-X UDP port (default 2237)")
    args = ap.parse_args()
    run(args.host, args.port)

if __name__ == "__main__":
    main()
