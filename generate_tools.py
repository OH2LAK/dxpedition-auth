#!/usr/bin/env python3
"""
DXpedition Authentication Tool Generator
=========================================

PRIMARY PURPOSE: Let calling stations cryptographically verify they are talking
to the real DXpedition station — not a pirate imitator.

SECONDARY PURPOSE: Let the DXpedition operator verify a calling station's identity.

Run this once to generate three customised tools:

  station_tool_<CALL>.html    — Web tool for the ham community (share publicly)
  operator_<CALL>.py          — Terminal dashboard for DXpedition operators
  ft8_bridge_<CALL>.py        — Auto-pushes current auth code to WSJT-X / FT8

USAGE:
  python generate_tools.py
  python generate_tools.py --callsign OH0X --output ./OH0X_tools/
  python generate_tools.py --callsign OH0X --key <existing_64_hex_chars>

CRYPTOGRAPHIC NOTES:
  All codes: HMAC-SHA256 keyed with the embedded 256-bit secret, output
  Base32-encoded and truncated to 5 characters.

  DXpedition time code  = HMAC(secret, "DXPED:<CALL>:<5min_window_number>")[:5]
    • Changes every 5 minutes.  Verified by ±1 window (15 min tolerance).
    • Station enters the received code into the web tool → AUTHENTIC / NOT AUTHENTIC.
    • This is the PRIMARY authentication — it proves the DXpedition is real.

  Station identity code = HMAC(secret, "STATION:<THEIR_CALL>:<DXPED_CALL>")[:5]
    • Permanent for the duration of the DXpedition.
    • Tied to the specific callsign pair — useless with any other DXpedition.
    • This is SECONDARY — useful for log integrity, not mandatory.

  FT8 / FT4 / FT2 integration:
    • Auth code fits in the 13-char free text field as "AUTH BVRTK" (10 chars).
    • ft8_bridge_*.py pushes the code to WSJT-X automatically via UDP (port 2237).
    • Station-side: ft8_monitor_*.py (optional, see docs) listens for the code
      in WSJT-X decode stream and auto-verifies it.
"""

import os
import sys
import hmac as _hmac
import hashlib
import secrets
import argparse
import time
from datetime import datetime, timezone

# ─── Cryptographic core ───────────────────────────────────────────────────────

WINDOW_SECONDS = 300   # 5-minute windows
BASE32_ALPHA   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

PHONETIC = {
    "A": "Alpha",   "B": "Bravo",   "C": "Charlie", "D": "Delta",
    "E": "Echo",    "F": "Foxtrot", "G": "Golf",    "H": "Hotel",
    "I": "India",   "J": "Juliet",  "K": "Kilo",    "L": "Lima",
    "M": "Mike",    "N": "November","O": "Oscar",   "P": "Papa",
    "Q": "Quebec",  "R": "Romeo",   "S": "Sierra",  "T": "Tango",
    "U": "Uniform", "V": "Victor",  "W": "Whiskey", "X": "X-ray",
    "Y": "Yankee",  "Z": "Zulu",
    "2": "Two",     "3": "Three",   "4": "Four",    "5": "Five",
    "6": "Six",     "7": "Seven",
}


def b32_encode(data: bytes) -> str:
    """RFC 4648 Base32 without padding. Identical algorithm used in the JS tool."""
    result, buf, bits = [], 0, 0
    for byte in data:
        buf = (buf << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            result.append(BASE32_ALPHA[(buf >> bits) & 31])
    if bits > 0:
        result.append(BASE32_ALPHA[(buf << (5 - bits)) & 31])
    return "".join(result)


def hmac5(key_hex: str, message: str) -> str:
    key    = bytes.fromhex(key_hex)
    digest = _hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()
    return b32_encode(digest)[:5]


def dxped_time_code(key_hex: str, dxped: str, window: int = None) -> str:
    if window is None:
        window = int(time.time() // WINDOW_SECONDS)
    return hmac5(key_hex, f"DXPED:{dxped.upper().strip()}:{window}")


def station_code(key_hex: str, station: str, dxped: str) -> str:
    return hmac5(key_hex, f"STATION:{station.upper().strip()}:{dxped.upper().strip()}")


def phonetic(code: str) -> str:
    return "  ".join(PHONETIC.get(c, c) for c in code.upper())


def generate_key() -> str:
    return secrets.token_bytes(32).hex()


# ─────────────────────────────────────────────────────────────────────────────
#  HTML STATION TOOL TEMPLATE
#  Primary tab: Verify the DXpedition is real
#  Secondary tab: Station identity code (optional)
# ─────────────────────────────────────────────────────────────────────────────

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify __DXPED__ &bull; DX Auth</title>
  <style>
    :root {
      --bg:      #0b0f0b;
      --surface: #131a13;
      --border:  #1e331e;
      --green:   #00e050;
      --green2:  #00a038;
      --green3:  #004a1e;
      --red:     #ff3311;
      --yellow:  #ffcc00;
      --cyan:    #00ccbb;
      --dim:     #4a664a;
      --text:    #c8e8c8;
      --font:    'Courier New', 'Lucida Console', monospace;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      min-height: 100vh;
      padding: 16px;
      font-size: 15px;
    }

    /* ── Header ────────────────────────────────── */
    .header {
      text-align: center;
      border: 1px solid var(--border);
      background: var(--surface);
      padding: 18px 12px 14px;
      margin-bottom: 18px;
      border-radius: 4px;
    }
    .header .eyebrow { font-size: 11px; letter-spacing: 3px; color: var(--dim); margin-bottom: 6px; }
    .header .callsign {
      font-size: 42px; font-weight: bold; color: var(--green);
      letter-spacing: 10px; text-shadow: 0 0 22px #00ff6055;
    }
    .header .tagline { font-size: 12px; color: var(--dim); margin-top: 8px; letter-spacing: 1px; }

    /* ── Tabs ──────────────────────────────────── */
    .tabs { display: flex; gap: 3px; margin-bottom: -1px; flex-wrap: wrap; }
    .tab {
      padding: 9px 18px; cursor: pointer;
      border: 1px solid var(--border); border-bottom: none;
      background: var(--bg); color: var(--dim);
      border-radius: 4px 4px 0 0;
      font-family: var(--font); font-size: 12px; letter-spacing: 1px;
      transition: color .15s, background .15s;
    }
    .tab:hover { color: var(--text); }
    .tab.active { background: var(--surface); color: var(--green); }
    .tab.primary { font-weight: bold; font-size: 13px; }

    /* ── Panels ─────────────────────────────────── */
    .panel-wrap {
      border: 1px solid var(--border); background: var(--surface);
      border-radius: 0 4px 4px 4px; padding: 26px;
    }
    .panel { display: none; }
    .panel.active { display: block; }

    /* ── Form ─────────────────────────────────── */
    label { display: block; font-size: 11px; color: var(--dim); letter-spacing: 1px; margin-bottom: 5px; }
    input[type=text] {
      background: #0d140d; border: 1px solid var(--border); border-radius: 3px;
      color: var(--green); font-family: var(--font); font-size: 22px;
      padding: 10px 14px; letter-spacing: 5px; text-transform: uppercase;
      outline: none; transition: border-color .2s;
      width: 100%; max-width: 320px;
    }
    input[type=text]:focus { border-color: var(--green2); }
    input[type=text]::placeholder { color: var(--dim); font-size: 14px; letter-spacing: 2px; }
    .btn {
      display: inline-block; margin-top: 14px; padding: 10px 28px;
      background: var(--green3); color: var(--green);
      border: 1px solid var(--green2); border-radius: 3px;
      font-family: var(--font); font-size: 13px; letter-spacing: 2px;
      cursor: pointer; transition: background .15s;
    }
    .btn:hover { background: var(--green2); color: #fff; }
    .btn:active { background: var(--green); color: #000; }
    .fixed-field {
      background: #0d140d; border: 1px solid var(--border); border-radius: 3px;
      color: var(--dim); font-family: var(--font); font-size: 22px;
      padding: 10px 14px; letter-spacing: 5px;
      width: 100%; max-width: 320px; margin-bottom: 16px;
    }

    /* ── Live code display ─────────────────────── */
    .live-section {
      background: #0d170d; border: 1px solid var(--border);
      border-radius: 4px; padding: 20px 24px; margin-bottom: 20px;
    }
    .live-label { font-size: 11px; color: var(--dim); letter-spacing: 2px; margin-bottom: 10px; }
    .live-code {
      font-size: 56px; font-weight: bold; letter-spacing: 18px;
      color: var(--green); text-shadow: 0 0 24px #00ee5560;
      margin-bottom: 8px; line-height: 1.1;
    }
    .live-phonetic { font-size: 12px; color: var(--dim); letter-spacing: 1px; margin-bottom: 14px; }
    .timer-bar { height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; margin-bottom: 4px; }
    .timer-fill { height: 100%; background: var(--green2); transition: width 1s linear; }
    .timer-label { font-size: 11px; color: var(--dim); letter-spacing: 1px; }
    .timer-label span { color: var(--yellow); }

    /* ── Result box ────────────────────────────── */
    .result-box {
      margin-top: 18px; padding: 18px 22px;
      border: 1px solid var(--border); border-radius: 4px;
      background: #0d170d; display: none;
    }
    .result-box.visible { display: block; }
    .result-box.ok  { border-color: var(--green2); }
    .result-box.bad { border-color: var(--red); }
    .verdict-ok  { color: var(--green);  font-size: 24px; letter-spacing: 2px; margin-bottom: 8px; }
    .verdict-bad { color: var(--red);    font-size: 24px; letter-spacing: 2px; margin-bottom: 8px; }
    .verdict-detail { font-size: 13px; color: var(--dim); line-height: 1.6; }

    /* ── Station code result ────────────────────── */
    .code-display {
      font-size: 52px; font-weight: bold; letter-spacing: 16px;
      color: var(--green); text-shadow: 0 0 20px #00ee5560; margin-bottom: 8px;
    }
    .phonetic-row { font-size: 13px; color: var(--dim); letter-spacing: 1px; margin-bottom: 14px; }
    .instruction {
      font-size: 13px; color: var(--text); line-height: 1.7;
      border-top: 1px solid var(--border); padding-top: 12px;
    }
    .instruction span { color: var(--green); }

    /* ── FT8 box ───────────────────────────────── */
    .ft8-code-box {
      background: #0d140d; border: 1px solid var(--border); border-radius: 3px;
      padding: 14px 18px; margin: 12px 0; display: flex; align-items: center; gap: 14px;
    }
    .ft8-code { font-size: 24px; letter-spacing: 6px; color: var(--cyan); }
    .copy-btn {
      padding: 6px 14px; font-family: var(--font); font-size: 11px; letter-spacing: 1px;
      background: #0d1f1a; border: 1px solid var(--cyan); color: var(--cyan);
      border-radius: 3px; cursor: pointer; transition: background .15s;
    }
    .copy-btn:hover { background: var(--cyan); color: #000; }

    /* ── Info box ──────────────────────────────── */
    .info-box {
      margin-top: 18px; padding: 14px 18px;
      border-left: 3px solid var(--green3); background: #0d150d;
      font-size: 12px; color: var(--dim); line-height: 1.8;
    }
    .info-box strong { color: var(--text); }
    .secondary-badge {
      display: inline-block; font-size: 10px; letter-spacing: 2px;
      color: var(--dim); border: 1px solid var(--border);
      padding: 2px 8px; border-radius: 2px; margin-bottom: 16px;
    }

    footer {
      text-align: center; margin-top: 22px;
      font-size: 11px; color: var(--dim); letter-spacing: 1px;
    }
  </style>
</head>
<body>

<div class="header">
  <div class="eyebrow">&#9670; DXPEDITION AUTHENTICATION &#9670;</div>
  <div class="callsign">__DXPED__</div>
  <div class="tagline">Verify you are in contact with the real station &mdash; not a pirate</div>
</div>

<div class="tabs">
  <div class="tab primary active" onclick="switchTab('verify')">&#10003; VERIFY __DXPED__</div>
  <div class="tab" onclick="switchTab('station')">&#9670; YOUR CODE</div>
  <div class="tab" onclick="switchTab('ft8')">&#9700; FT8 / DIGITAL</div>
  <div class="tab" onclick="switchTab('howto')">? HOW TO USE</div>
</div>

<div class="panel-wrap">

  <!-- ══════════════════════════════════════════════════════════
       TAB 1 — VERIFY DXPEDITION  (PRIMARY)
       ══════════════════════════════════════════════════════════ -->
  <div class="panel active" id="panel-verify">

    <!-- Live code display -->
    <div class="live-section">
      <div class="live-label">CURRENT EXPECTED CODE FROM __DXPED__</div>
      <div class="live-code" id="live-code">&#8943;</div>
      <div class="live-phonetic" id="live-phonetic"></div>
      <div class="timer-bar"><div class="timer-fill" id="timer-fill" style="width:100%"></div></div>
      <div class="timer-label">Next code in <span id="timer-countdown">--:--</span></div>
    </div>

    <!-- Verification input -->
    <label>CODE YOU RECEIVED FROM __DXPED__ OVER THE AIR</label>
    <input type="text" id="inp-rxcode" maxlength="5" placeholder="5 CHARS"
           oninput="onRxInput()" onkeydown="if(event.key==='Enter')verifyCode()">
    <button class="btn" onclick="verifyCode()">&#10003; VERIFY</button>

    <div class="result-box" id="ver-result">
      <div id="ver-verdict"></div>
      <div class="verdict-detail" id="ver-detail"></div>
    </div>

    <div class="info-box">
      <strong>How to use:</strong> Listen for __DXPED__ to announce their
      authentication code over the air (phonetically). Enter the 5 characters
      above and click Verify. A pirate station cannot produce a matching code.
      The code changes every 5 minutes &mdash; the tool accepts one window either
      side for clock tolerance.
    </div>
  </div>

  <!-- ══════════════════════════════════════════════════════════
       TAB 2 — YOUR STATION CODE  (SECONDARY)
       ══════════════════════════════════════════════════════════ -->
  <div class="panel" id="panel-station">
    <div class="secondary-badge">OPTIONAL &bull; FOR LOG INTEGRITY</div>

    <label>YOUR CALLSIGN</label>
    <input type="text" id="inp-station" maxlength="12" placeholder="e.g. OH2RAK"
           oninput="clearResult('gen-result')" onkeydown="if(event.key==='Enter')genCode()">

    <label style="margin-top:16px">DXPEDITION (fixed)</label>
    <div class="fixed-field">__DXPED__</div>

    <button class="btn" onclick="genCode()">&#9654; GET MY CODE</button>

    <div class="result-box" id="gen-result">
      <div class="code-display" id="gen-code">-----</div>
      <div class="phonetic-row" id="gen-phonetic"></div>
      <div class="instruction">
        If the operator asks: say <em>"My auth is
        <span id="gen-code-inline">-----</span>"</em> using the phonetic alphabet.<br><br>
        This code is <strong>permanent</strong> and unique to the pair
        (<span id="gen-callsign"></span> &harr; <span>__DXPED__</span>).
      </div>
    </div>

    <div class="info-box">
      <strong>Why this is optional:</strong> The DXpedition broadcasting their
      time code (Verify tab) is what stops pirate stations. Your station code
      lets the operator cross-check their log, but exchanging it is not required
      for the contact to be valid.
    </div>
  </div>

  <!-- ══════════════════════════════════════════════════════════
       TAB 3 — FT8 / DIGITAL MODES
       ══════════════════════════════════════════════════════════ -->
  <div class="panel" id="panel-ft8">

    <div class="live-label" style="margin-bottom:12px">
      CURRENT FREE TEXT FOR FT8 / FT4 / FT2 / JS8CALL
    </div>

    <div class="ft8-code-box">
      <div class="ft8-code" id="ft8-text">AUTH -----</div>
      <button class="copy-btn" onclick="copyFt8()">COPY</button>
    </div>
    <div class="timer-label" style="margin-bottom:20px">
      Valid for <span id="ft8-countdown" style="color:var(--yellow)">--:--</span>
      &nbsp;|&nbsp; Next: <span id="ft8-next" style="color:var(--dim)">-----</span>
    </div>

    <div class="info-box" style="margin-bottom:20px">
      <strong>FT8 / FT4 / FT2 procedure:</strong><br>
      The DXpedition operator pastes the code above into WSJT-X &rarr;
      <em>Settings &rarr; Advanced &rarr; Free text</em> (or uses the
      <code>ft8_bridge_*.py</code> script to auto-update it).
      The code is sent as a free-text transmission alongside the normal
      QSO exchange &mdash; for example, after the <em>73</em>.<br><br>
      <strong>Example sequence:</strong><br>
      <code style="color:var(--text)">
        CQ&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;OH0X JP90<br>
        OH2RAK OH0X -12<br>
        OH0X OH2RAK R-08<br>
        OH0X OH2RAK RR73<br>
        OH0X&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;AUTH BVRTK&nbsp;&nbsp;&nbsp;&larr; auth code in free text
      </code>
    </div>

    <div class="info-box">
      <strong>Receiving station auto-verification:</strong><br>
      Run <code>ft8_bridge_<em>CALL</em>.py</code> alongside WSJT-X.
      It listens on UDP port 2237 for any decoded free-text message containing
      the current auth code from __DXPED__, and automatically flags the contact
      as verified &mdash; no manual entry needed.<br><br>
      <strong>Supported modes:</strong> FT8 (15 s cycle) &bull; FT4 (7.5 s) &bull;
      FT2 (3.8 s, experimental) &bull; JS8Call (free text field)
    </div>
  </div>

  <!-- ══════════════════════════════════════════════════════════
       TAB 4 — HOW TO USE
       ══════════════════════════════════════════════════════════ -->
  <div class="panel" id="panel-howto">
    <div style="line-height:1.9; font-size:13px; color:var(--text);">

      <p style="color:var(--green); font-size:15px; letter-spacing:2px; margin-bottom:18px;">
        &#9670; COMPLETE WORKFLOW
      </p>

      <p><strong style="color:var(--green);">THE PIRATE PROBLEM</strong></p>
      <p>A pirate station transmits on __DXPED__&rsquo;s frequency pretending to be the
      real DXpedition. Stations make contacts and log them &mdash; but the QSO never
      happened. This tool gives every station a way to independently verify the
      DXpedition is genuine.</p>
      <br>

      <p><strong style="color:var(--green);">FOR CALLING STATIONS</strong></p>
      <ol style="padding-left:20px; line-height:2;">
        <li>Listen for __DXPED__ to announce their authentication code phonetically,
            or watch for it in their FT8 free-text transmission.</li>
        <li>Go to the <em>Verify __DXPED__</em> tab and enter the 5-character code.</li>
        <li>&#10003;&nbsp;<strong>AUTHENTIC</strong> &rarr; you are in contact with the
            real station. Log with confidence.</li>
        <li>&#10007;&nbsp;<strong>NOT AUTHENTIC</strong> &rarr; possible pirate. Do not
            log. Try again or QSY.</li>
      </ol>
      <br>

      <p><strong style="color:var(--green);">FOR DXPEDITION OPERATORS</strong></p>
      <ol style="padding-left:20px; line-height:2;">
        <li>Run <code>operator___DXPED__.py</code> on the operating desk laptop.</li>
        <li>Announce the displayed 5-character code over the air every few QSOs,
            or whenever a station asks for it.</li>
        <li>For FT8/FT4: run <code>ft8_bridge___DXPED__.py</code> alongside WSJT-X &mdash;
            it auto-inserts the code as free text and updates it every 5 minutes.</li>
        <li><em>Optionally</em>: when a station gives you their code, type their callsign
            in the operator tool to check it against your log.</li>
      </ol>
      <br>

      <p><strong style="color:var(--green);">CODE TIMING</strong></p>
      <p>The DXpedition code changes every <strong>5 minutes</strong>.
      This tool accepts the code from one window either side (15 minutes total)
      to allow for clock differences between stations. If verification fails just
      after a code change, ask the operator to send their current code again.</p>
      <br>

      <p style="color:var(--dim); font-size:12px; border-top:1px solid var(--border); padding-top:14px;">
        All cryptography runs in your browser. No data leaves your device.
        Works fully offline once loaded.
      </p>
    </div>
  </div>

</div>

<footer>
  __DXPED__ Authentication &bull; Works offline &bull; No data leaves your device
</footer>

<script>
// ─── Embedded configuration ───────────────────────────────────────────────────
const KEY_HEX  = "__KEY__";
const DXPED    = "__DXPED__";
const WIN_SECS = __WIN_SECS__;

// ─── Base32 (RFC 4648, no padding — identical to Python implementation) ───────
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32(bytes) {
  let r = "", buf = 0, bits = 0;
  for (const b of bytes) {
    buf = (buf << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; r += B32[(buf >>> bits) & 31]; }
  }
  if (bits > 0) r += B32[(buf << (5 - bits)) & 31];
  return r;
}

// ─── HMAC-SHA256 via Web Crypto API ──────────────────────────────────────────
function hex2bytes(hex) {
  const b = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < hex.length; i += 2) b[i >> 1] = parseInt(hex.substr(i, 2), 16);
  return b;
}
async function hmac5(keyHex, msg) {
  const k = await crypto.subtle.importKey(
    "raw", hex2bytes(keyHex), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg));
  return base32(new Uint8Array(sig)).slice(0, 5);
}
async function dxpedCode(win) {
  return hmac5(KEY_HEX, "DXPED:" + DXPED + ":" + win);
}
async function stationCode(call) {
  return hmac5(KEY_HEX, "STATION:" + call.toUpperCase().trim() + ":" + DXPED);
}

// ─── Phonetic ─────────────────────────────────────────────────────────────────
const NATO = {A:"Alpha",B:"Bravo",C:"Charlie",D:"Delta",E:"Echo",F:"Foxtrot",
  G:"Golf",H:"Hotel",I:"India",J:"Juliet",K:"Kilo",L:"Lima",M:"Mike",
  N:"November",O:"Oscar",P:"Papa",Q:"Quebec",R:"Romeo",S:"Sierra",T:"Tango",
  U:"Uniform",V:"Victor",W:"Whiskey",X:"X-ray",Y:"Yankee",Z:"Zulu",
  "2":"Two","3":"Three","4":"Four","5":"Five","6":"Six","7":"Seven"};
const phonetic = c => c.toUpperCase().split("").map(x => NATO[x]||x).join("  ");

// ─── Tab switching ────────────────────────────────────────────────────────────
function switchTab(name) {
  const names = ["verify","station","ft8","howto"];
  document.querySelectorAll(".tab").forEach((t,i)  => t.classList.toggle("active", names[i]===name));
  document.querySelectorAll(".panel").forEach((p,i) => p.classList.toggle("active", names[i]===name));
}
function clearResult(id) { document.getElementById(id).classList.remove("visible","ok","bad"); }

// ─── Live timer & code update ─────────────────────────────────────────────────
let _liveCode = "", _liveWin = -1;
async function updateLive() {
  const nowSec  = Math.floor(Date.now() / 1000);
  const curWin  = Math.floor(nowSec / WIN_SECS);
  const remain  = WIN_SECS - (nowSec % WIN_SECS);
  const mm      = String(Math.floor(remain / 60)).padStart(2,"0");
  const ss      = String(remain % 60).padStart(2,"0");
  const fill    = (remain / WIN_SECS * 100).toFixed(1) + "%";

  document.getElementById("timer-fill").style.width = fill;
  document.getElementById("timer-countdown").textContent = mm + ":" + ss;
  document.getElementById("ft8-countdown").textContent  = mm + ":" + ss;

  if (curWin !== _liveWin) {
    _liveWin  = curWin;
    _liveCode = await dxpedCode(curWin);
    const nextCode = await dxpedCode(curWin + 1);
    document.getElementById("live-code").textContent    = _liveCode;
    document.getElementById("live-phonetic").textContent = phonetic(_liveCode);
    document.getElementById("ft8-text").textContent     = "AUTH " + _liveCode;
    document.getElementById("ft8-next").textContent     = nextCode;
  }
}
setInterval(updateLive, 1000);
updateLive();

// ─── Verify DXpedition code ───────────────────────────────────────────────────
async function onRxInput() {
  const v = document.getElementById("inp-rxcode").value.trim().toUpperCase();
  if (v.length === 5) await verifyCode();
  else clearResult("ver-result");
}

async function verifyCode() {
  const received = document.getElementById("inp-rxcode").value.trim().toUpperCase();
  if (received.length !== 5) {
    const el = document.getElementById("inp-rxcode");
    el.style.borderColor = "var(--red)";
    setTimeout(() => el.style.borderColor = "", 700);
    return;
  }
  const curWin = Math.floor(Date.now() / 1000 / WIN_SECS);
  const labels = {"-1":"previous window (code just changed)", "0":"current window", "1":"next window"};
  for (const offset of [0, -1, 1]) {
    if (received === await dxpedCode(curWin + offset)) {
      const box = document.getElementById("ver-result");
      document.getElementById("ver-verdict").innerHTML = '<div class="verdict-ok">&#10003; AUTHENTIC</div>';
      document.getElementById("ver-detail").textContent =
        "Code matches the " + labels[offset] + ". " +
        "You are in contact with the real " + DXPED + " station.";
      box.className = "result-box visible ok";
      return;
    }
  }
  const box = document.getElementById("ver-result");
  document.getElementById("ver-verdict").innerHTML = '<div class="verdict-bad">&#10007; NOT AUTHENTIC</div>';
  document.getElementById("ver-detail").textContent =
    "Code does not match any valid 5-minute window. " +
    "This may be a pirate station. Check you copied all 5 characters correctly, " +
    "then ask " + DXPED + " to announce their current code again.";
  box.className = "result-box visible bad";
}

// ─── Generate station code ────────────────────────────────────────────────────
async function genCode() {
  const call = document.getElementById("inp-station").value.trim().toUpperCase();
  if (call.length < 3) {
    const el = document.getElementById("inp-station");
    el.style.borderColor = "var(--red)";
    setTimeout(() => el.style.borderColor = "", 700);
    return;
  }
  const code = await stationCode(call);
  document.getElementById("gen-code").textContent         = code;
  document.getElementById("gen-code-inline").textContent  = code;
  document.getElementById("gen-callsign").textContent     = call;
  document.getElementById("gen-phonetic").textContent     = phonetic(code);
  const box = document.getElementById("gen-result");
  box.className = "result-box visible";
}

// ─── FT8 copy helper ──────────────────────────────────────────────────────────
function copyFt8() {
  const text = document.getElementById("ft8-text").textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector(".copy-btn");
    btn.textContent = "COPIED"; btn.style.background = "var(--cyan)"; btn.style.color = "#000";
    setTimeout(() => { btn.textContent = "COPY"; btn.style.background = ""; btn.style.color = ""; }, 1500);
  });
}
</script>
</body>
</html>
"""

# ─────────────────────────────────────────────────────────────────────────────
#  OPERATOR TOOL TEMPLATE
# ─────────────────────────────────────────────────────────────────────────────

OPERATOR_TEMPLATE = """\
#!/usr/bin/env python3
\"\"\"
DXpedition Operator Authentication Tool  —  __DXPED__
======================================================

PRIMARY  : Shows the current 5-char time code to broadcast to callers.
SECONDARY: Look up the expected code for any calling station's callsign.

USAGE:
  python operator___DXPED_SAFE__.py               Live dashboard
  python operator___DXPED_SAFE__.py <CALLSIGN>    Quick station lookup, then exit
\"\"\"

import os, sys, hmac as _hmac, hashlib, time
from datetime import datetime, timezone

DXPED          = "__DXPED__"
SECRET_KEY_HEX = "__KEY__"
WINDOW_SECS    = __WIN_SECS__

BASE32_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
PHONETIC = {
    "A":"Alpha","B":"Bravo","C":"Charlie","D":"Delta","E":"Echo","F":"Foxtrot",
    "G":"Golf","H":"Hotel","I":"India","J":"Juliet","K":"Kilo","L":"Lima",
    "M":"Mike","N":"November","O":"Oscar","P":"Papa","Q":"Quebec","R":"Romeo",
    "S":"Sierra","T":"Tango","U":"Uniform","V":"Victor","W":"Whiskey",
    "X":"X-ray","Y":"Yankee","Z":"Zulu",
    "2":"Two","3":"Three","4":"Four","5":"Five","6":"Six","7":"Seven",
}

def _b32(data):
    result, buf, bits = [], 0, 0
    for byte in data:
        buf = (buf << 8) | byte; bits += 8
        while bits >= 5:
            bits -= 5; result.append(BASE32_ALPHA[(buf >> bits) & 31])
    if bits > 0: result.append(BASE32_ALPHA[(buf << (5 - bits)) & 31])
    return "".join(result)

def _hmac5(message):
    key = bytes.fromhex(SECRET_KEY_HEX)
    return _b32(_hmac.new(key, message.encode(), hashlib.sha256).digest())[:5]

def get_dxped_code(window=None):
    if window is None: window = int(time.time() // WINDOW_SECS)
    return _hmac5(f"DXPED:{DXPED}:{window}")

def get_station_code(call):
    return _hmac5(f"STATION:{call.upper().strip()}:{DXPED}")

def ph(code): return "  ".join(PHONETIC.get(c, c) for c in code.upper())

# ANSI
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
    win  = int(time.time() // WINDOW_SECS)
    print(f"\\n  {D}DXpedition :{RST}  {DXPED}")
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
                        if ch in ("\\r","\\n"):
                            call = buf.strip().upper(); buf = ""
                            if len(call) >= 3: history.append((call, get_station_code(call)))
                            last_t = 0
                        elif ch in ("\\x7f","\\x08"): buf = buf[:-1]
                        elif ch.isprintable(): buf += ch
                except (IOError, OSError): time.sleep(0.1)
            else:
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if posix and old: termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
        clr(); print(f"\\n  {D}73 de {DXPED}{RST}\\n")

def main():
    if len(sys.argv) == 2 and sys.argv[1] not in ("-h","--help"):
        quick_lookup(sys.argv[1])
    else:
        live()

if __name__ == "__main__":
    main()
"""

# ─────────────────────────────────────────────────────────────────────────────
#  FT8 BRIDGE TEMPLATE
#  Pushes the current auth code to WSJT-X via UDP (port 2237).
#  Also monitors incoming decoded messages for the auth code.
# ─────────────────────────────────────────────────────────────────────────────

FT8_BRIDGE_TEMPLATE = """\
#!/usr/bin/env python3
\"\"\"
FT8 / WSJT-X Authentication Bridge  —  __DXPED__
=================================================

Runs alongside WSJT-X on the DXpedition operating computer.

  1. Every time the 5-minute auth code changes, this script automatically
     updates the WSJT-X free text field to  "AUTH XXXXX".
  2. Monitors decoded FT8 messages from WSJT-X and logs contacts where
     a calling station's auth code appears in their transmission.

REQUIREMENTS:
  • WSJT-X Settings → Reporting → UDP Server enabled on 127.0.0.1:2237

USAGE:
  python ft8_bridge___DXPED_SAFE__.py
  python ft8_bridge___DXPED_SAFE__.py --host 127.0.0.1 --port 2237
\"\"\"

import argparse, hmac as _hmac, hashlib, socket, struct, sys, time, threading
from datetime import datetime, timezone

DXPED          = "__DXPED__"
SECRET_KEY_HEX = "__KEY__"
WINDOW_SECS    = __WIN_SECS__

# WSJT-X UDP protocol constants (NetworkMessage.hpp)
WSJTX_MAGIC  = 0xADBCCBDA
WSJTX_SCHEMA = 2
MSG_FREE_TEXT = 9   # FreeText   (external → WSJT-X): set TX free text
MSG_DECODE    = 2   # Decode     (WSJT-X → external): decoded message
MSG_STATUS    = 1   # Status     (WSJT-X → external): operational status

# ─── Crypto ──────────────────────────────────────────────────────────────────
BASE32_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
def _b32(data):
    r, buf, bits = [], 0, 0
    for b in data:
        buf=(buf<<8)|b; bits+=8
        while bits>=5: bits-=5; r.append(BASE32_ALPHA[(buf>>bits)&31])
    if bits>0: r.append(BASE32_ALPHA[(buf<<(5-bits))&31])
    return "".join(r)

def current_code(window=None):
    if window is None: window = int(time.time() // WINDOW_SECS)
    key = bytes.fromhex(SECRET_KEY_HEX)
    d = _hmac.new(key, f"DXPED:{DXPED}:{window}".encode(), hashlib.sha256).digest()
    return _b32(d)[:5]

def expected_station_code(call):
    key = bytes.fromhex(SECRET_KEY_HEX)
    d = _hmac.new(key, f"STATION:{call.upper().strip()}:{DXPED}".encode(), hashlib.sha256).digest()
    return _b32(d)[:5]

# ─── Qt QDataStream packing ───────────────────────────────────────────────────
def _qstring(s):
    \"\"\"Pack str as Qt QDataStream QString (UTF-16 BE, 4-byte length prefix).\"\"\"
    if s is None: return struct.pack(">I", 0xFFFFFFFF)
    b = s.encode("utf-16-be")
    return struct.pack(">I", len(b)) + b

def _qbytearray(b):
    \"\"\"Pack bytes as Qt QDataStream QByteArray.\"\"\"
    if b is None: return struct.pack(">I", 0xFFFFFFFF)
    return struct.pack(">I", len(b)) + b

def _unpack_qstring(data, offset):
    \"\"\"Unpack a QString from raw bytes. Returns (string, new_offset).\"\"\"
    length = struct.unpack_from(">I", data, offset)[0]; offset += 4
    if length == 0xFFFFFFFF: return None, offset
    s = data[offset:offset+length].decode("utf-16-be", errors="replace")
    return s, offset + length

def _unpack_qbytearray(data, offset):
    length = struct.unpack_from(">I", data, offset)[0]; offset += 4
    if length == 0xFFFFFFFF: return None, offset
    return data[offset:offset+length], offset + length

# ─── WSJT-X message builders ─────────────────────────────────────────────────
def build_free_text_packet(text, client_id="DXAuth", send_now=False):
    \"\"\"Build a FreeText message (type 9) to send to WSJT-X.\"\"\"
    hdr  = struct.pack(">III", WSJTX_MAGIC, WSJTX_SCHEMA, MSG_FREE_TEXT)
    hdr += _qbytearray(client_id.encode("utf-8"))
    body = _qstring(text) + struct.pack("?", send_now)
    return hdr + body

# ─── Decode message parser ────────────────────────────────────────────────────
def parse_decode(data):
    \"\"\"Parse a WSJT-X Decode message. Returns dict or None on error.\"\"\"
    try:
        magic, schema, msg_type = struct.unpack_from(">III", data, 0)
        if magic != WSJTX_MAGIC or msg_type != MSG_DECODE: return None
        offset = 12
        _, offset     = _unpack_qbytearray(data, offset)      # client id
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

# ─── Main bridge logic ────────────────────────────────────────────────────────
G="\033[92m"; D="\033[2m"; Y="\033[93m"; C="\033[96m"; R="\033[91m"; RST="\033[0m"

def ts(): return datetime.now(timezone.utc).strftime("%H:%M:%S")

def run(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)

    last_win  = -1
    last_code = ""

    print(f"\\n  {G}FT8 Authentication Bridge  ·  {DXPED}{RST}")
    print(f"  {D}Listening on {host}:{port}  |  WSJT-X must have UDP enabled{RST}")
    print(f"  {D}{'─'*56}{RST}\\n")

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
            # ── Check if code window has rolled over ──
            win  = int(time.time() // WINDOW_SECS)
            code = current_code(win)
            if win != last_win:
                last_win, last_code = win, code
                remain = WINDOW_SECS - (time.time() % WINDOW_SECS)
                print(f"  {ts()}  {Y}New 5-min window  →  code: {G}{code}  "
                      f"{D}(valid {int(remain//60):02d}:{int(remain%60):02d}){RST}")
                push_code(code)

            # ── Listen for decoded messages from WSJT-X ──
            try:
                data, _ = sock.recvfrom(4096)
                dec = parse_decode(data)
                if dec and dec["new"] and dec["message"]:
                    msg = dec["message"].upper()
                    # Detect own auth code in incoming decodes (e.g. "AUTH BVRTK")
                    if f"AUTH {code}" in msg:
                        print(f"  {ts()}  {C}✓ Received own auth code in decode: {dec['message']}{RST}")
                    # Detect a station code from a calling station
                    # Format: callsign sends free text containing their 5-char code
                    # This is informational only — not automated verification
                    words = msg.split()
                    if len(words) >= 2 and len(words[-1]) == 5:
                        call = words[0]
                        rcvd = words[-1]
                        exp  = expected_station_code(call)
                        if rcvd == exp:
                            print(f"  {ts()}  {G}✓ Station code match: {call}  code: {rcvd}{RST}")
            except socket.timeout:
                pass

    except KeyboardInterrupt:
        print(f"\\n  {D}73 de {DXPED}{RST}\\n")
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
"""

# ─────────────────────────────────────────────────────────────────────────────
#  Generator
# ─────────────────────────────────────────────────────────────────────────────

def safe_call(call): return "".join(c if c.isalnum() else "_" for c in call.upper())


def apply(template, call, key):
    return (template
            .replace("__DXPED__", call.upper())
            .replace("__DXPED_SAFE__", safe_call(call))
            .replace("__KEY__", key)
            .replace("__WIN_SECS__", str(WINDOW_SECONDS)))


def main():
    ap = argparse.ArgumentParser(
        description="Generate DXpedition authentication tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--callsign", "-c")
    ap.add_argument("--key",      "-k")
    ap.add_argument("--output",   "-o", default=".")
    args = ap.parse_args()

    call = args.callsign
    if not call:
        print("\n  DXpedition Authentication Tool Generator")
        print("  " + "─" * 42)
        call = input("  DXpedition callsign: ").strip().upper()
    call = call.upper().strip()
    if not call:
        print("  ERROR: callsign required."); sys.exit(1)

    if args.key:
        key = args.key.strip().lower()
        if len(key) != 64 or not all(c in "0123456789abcdef" for c in key):
            print("  ERROR: key must be 64 hex chars."); sys.exit(1)
        print(f"\n  Using existing key for {call}.")
    else:
        key = generate_key()
        print(f"\n  Generated new key for {call}.")
        print(f"  KEY (back this up): {key}\n")

    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=True)
    sc  = safe_call(call)

    files = [
        (f"station_tool_{sc}.html",   apply(HTML_TEMPLATE,        call, key)),
        (f"operator_{sc}.py",         apply(OPERATOR_TEMPLATE,    call, key)),
        (f"ft8_bridge_{sc}.py",       apply(FT8_BRIDGE_TEMPLATE,  call, key)),
    ]
    for fname, content in files:
        path = os.path.join(out, fname)
        with open(path, "w", encoding="utf-8") as f: f.write(content)
        os.chmod(path, 0o755)
        print(f"  ✔  {path}")

    win  = int(time.time() // WINDOW_SECONDS)
    curr = dxped_time_code(key, call, win)
    nxt  = dxped_time_code(key, call, win + 1)
    stn  = station_code(key, "OH2RAK", call)
    print(f"\n  Current DXped code : {curr}  ({phonetic(curr)})")
    print(f"  Next DXped code    : {nxt}  ({phonetic(nxt)})")
    print(f"  FT8 free text      : AUTH {curr}")
    print(f"  Example OH2RAK     : {stn}  ({phonetic(stn)})")
    print()
    print("  → Distribute station_tool_*.html to the ham community.")
    print("  → Keep operator_*.py and ft8_bridge_*.py on the DXped laptop only.")
    print()


if __name__ == "__main__":
    main()
