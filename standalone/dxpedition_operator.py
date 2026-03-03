#!/usr/bin/env python3
"""
DXpedition Operator Authentication Tool  (standalone / .exe version)
=====================================================================

Reads configuration from  dxpedition_config.json  next to this file.

PRIMARY  : Shows the current 4-char time code to broadcast to callers.
SECONDARY: Look up the expected code for any calling station's callsign.

USAGE:
  operator.exe                    Live dashboard
  operator.exe <CALLSIGN>         Quick station lookup, then exit
"""

import json, os, sys, hmac as _hmac, hashlib, time
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

# ─── Crypto ──────────────────────────────────────────────────────────────────

DIGIT_ALPHA  = "234567"
LETTER_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PHONETIC = {
    "A":"Alpha","B":"Bravo","C":"Charlie","D":"Delta","E":"Echo","F":"Foxtrot",
    "G":"Golf","H":"Hotel","I":"India","J":"Juliet","K":"Kilo","L":"Lima",
    "M":"Mike","N":"November","O":"Oscar","P":"Papa","Q":"Quebec","R":"Romeo",
    "S":"Sierra","T":"Tango","U":"Uniform","V":"Victor","W":"Whiskey",
    "X":"X-ray","Y":"Yankee","Z":"Zulu",
    "2":"Two","3":"Three","4":"Four","5":"Five","6":"Six","7":"Seven",
}

def _auth_code(message):
    """DLLL format: digit {2-7} + 3 letters {A-Z}. Never looks like a callsign."""
    key = bytes.fromhex(SECRET_KEY)
    d = _hmac.new(key, message.encode(), hashlib.sha256).digest()
    return (DIGIT_ALPHA[d[0]%6] + LETTER_ALPHA[d[1]%26] +
            LETTER_ALPHA[d[2]%26] + LETTER_ALPHA[d[3]%26])

def get_dxped_code(window=None):
    if window is None: window = int(time.time() // WINDOW_SECS)
    return _auth_code(f"DXPED:{DXPED}:{window}")

def get_station_code(call):
    return _auth_code(f"STATION:{call.upper().strip()}:{DXPED}")

def ph(code): return "  ".join(PHONETIC.get(c, c) for c in code.upper())

# ─── Display ─────────────────────────────────────────────────────────────────

G="\033[92m"; B="\033[1m"; D="\033[2m"; Y="\033[93m"; C="\033[96m"
R="\033[91m"; RST="\033[0m"; CLR="\033[H\033[J"

def clr(): print(CLR, end="", flush=True)

def progress_bar(fraction, width=42):
    n = int(fraction * width)
    return G + "\u2588" * n + D + "\u2591" * (width - n) + RST

def render(history):
    now     = time.time()
    win     = int(now // WINDOW_SECS)
    remain  = WINDOW_SECS - (now % WINDOW_SECS)
    frac    = remain / WINDOW_SECS
    prev    = get_dxped_code(win - 1)
    curr    = get_dxped_code(win)
    nxt     = get_dxped_code(win + 1)
    utc     = datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M:%S UTC")
    ft8txt  = f"AUTH {curr}"
    mm, ss  = int(remain // 60), int(remain % 60)

    clr()
    print(f"{D}{'─'*64}{RST}")
    print(f"  {B}{G}▶  DXpedition Auth  ·  {DXPED}{RST}  {D}(primary: prove YOU are real){RST}")
    print(f"{D}{'─'*64}{RST}")
    print()
    print(f"  {D}UTC:{RST}  {utc}")
    print()
    print(f"  {D}BROADCAST THIS CODE TO ALL CALLERS:{RST}")
    print()
    print(f"     {B}{G}{'  '.join(curr)}{RST}     {D}← CURRENT CODE{RST}")
    print()
    print(f"  {D}Phonetic:  {ph(curr)}{RST}")
    print()
    print(f"  {progress_bar(frac)}  {Y}{mm:02d}:{ss:02d}{RST}")
    print(f"  {D}Remaining in this 5-minute window{RST}")
    print()
    print(f"  {D}FT8/FT4 free text  →  {C}{ft8txt}{RST}  {D}(paste into WSJT-X or run ft8_bridge){RST}")
    print()
    print(f"  {D}{'─'*58}{RST}")
    print(f"  {D}Adjacent windows:   PREV {prev}   NEXT {nxt}{RST}")
    print(f"  {D}{'─'*58}{RST}")
    print()
    if history:
        print(f"  {D}STATION LOOKUPS  (secondary — optional):{RST}")
        for call, code in reversed(history[-6:]):
            print(f"  {C}{call:<12}{RST}  {B}{code}{RST}  {D}{ph(code)}{RST}")
        print()
    print(f"  {D}Type a callsign + ENTER to look up their expected code.{RST}")
    print(f"  {D}Ctrl+C to exit.{RST}")
    print()
    print(f"  {G}>{RST} ", end="", flush=True)

def quick_lookup(call):
    code = get_station_code(call)
    curr = get_dxped_code()
    print(f"\n  {D}DXpedition :{RST}  {DXPED}")
    print(f"  {D}Station    :{RST}  {call.upper()}")
    print(f"  {D}Auth code  :{RST}  {B}{G}{code}{RST}  {D}({ph(code)}){RST}")
    print()
    print(f"  {D}Current DXped code :{RST}  {B}{G}{curr}{RST}  {D}({ph(curr)}){RST}")
    print(f"  {D}FT8 free text      :{RST}  {C}AUTH {curr}{RST}")
    print()

def live():
    try:
        import select, termios, tty
        old = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())
        posix = True
    except Exception:
        old, posix = None, False

    history, buf, last_t = [], "", 0.0
    try:
        while True:
            now = time.time()
            if now - last_t >= 1.0:
                render(history)
                if buf: print(f"  {G}>{RST} {buf}", end="", flush=True)
                last_t = now
            if posix:
                try:
                    r, _, _ = select.select([sys.stdin], [], [], 0.1)
                    if r:
                        ch = sys.stdin.read(1)
                        if ch in ("\r","\n"):
                            call = buf.strip().upper(); buf = ""
                            if len(call) >= 3: history.append((call, get_station_code(call)))
                            last_t = 0
                        elif ch in ("\x7f","\x08"): buf = buf[:-1]
                        elif ch.isprintable(): buf += ch
                except (IOError, OSError): time.sleep(0.1)
            else:
                # Windows: use msvcrt for non-blocking input
                try:
                    import msvcrt
                    if msvcrt.kbhit():
                        ch = msvcrt.getwch()
                        if ch in ("\r", "\n"):
                            call = buf.strip().upper(); buf = ""
                            if len(call) >= 3: history.append((call, get_station_code(call)))
                            last_t = 0
                        elif ch == "\x08": buf = buf[:-1]
                        elif ch.isprintable(): buf += ch
                    else:
                        time.sleep(0.1)
                except ImportError:
                    time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if posix and old: termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        clr(); print(f"\n  {D}73 de {DXPED}{RST}\n")

def main():
    if len(sys.argv) == 2 and sys.argv[1] not in ("-h", "--help"):
        quick_lookup(sys.argv[1])
    else:
        live()

if __name__ == "__main__":
    main()
