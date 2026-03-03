# DXpedition Authentication System

> **Stop pirate stations.** Let every calling station independently verify they are working the real DXpedition — not an imitator.

[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Works offline](https://img.shields.io/badge/offline-yes-success)](README.md)
[![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](generate_tools.py)

---

## The Problem

During high-profile DXpeditions, pirate stations transmit on the same frequency
pretending to be the real expedition. Stations worldwide log contacts that never
happened. This is the problem this tool solves.

## How It Works

```
  DXpedition operator runs the operator tool on a desk laptop
        │
        │  "Our auth code is Three Foxtrot Kilo Alpha"   ← voice
        │  "AUTH 3FKA"                               ← FT8 free text
        │
        ▼  any listening station
  Opens station_tool_OH0X.html → Verify tab → enters 3FKA → AUTHENTIC ✔
```

A pirate cannot produce a matching code. The code changes every **5 minutes**.

---

## Quick Start — Windows (no Python required)

This is the easiest way to run the operator tools during the DXpedition.

### 1 — Generate your tools (one-time setup)

Someone on the team with Python installed runs this **once** before the trip:

```bash
python generate_tools.py --callsign OH0X --output ./OH0X_tools/
```

```
  Generated new key for OH0X.
  KEY (back this up): a3f2c1d4e5...   ← write this down

  ✔  OH0X_tools/station_tool_OH0X.html
  ✔  OH0X_tools/operator_OH0X.py
  ✔  OH0X_tools/ft8_bridge_OH0X.py
  ✔  OH0X_tools/dxpedition_config.json
```

> ⚠️ **Back up the key.** To regenerate tools later:
> `python generate_tools.py --callsign OH0X --key <saved_key>`

### 2 — Download the Windows executables

Download `operator.exe` and `ft8_bridge.exe` from the latest
[GitHub Release](../../releases).

### 3 — Copy three files to the operating laptop

```
OH0X_tools/
  operator.exe
  ft8_bridge.exe
  dxpedition_config.json   ← created by generate_tools.py
```

No Python needed on this machine.

### 4 — Double-click `operator.exe`

```
  ──────────────────────────────────────────────────────────────────
  ▶  DXpedition Auth  ·  OH0X   (primary: prove YOU are real)

  UTC:  2024-11-15  14:22:08 UTC

  BROADCAST THIS CODE TO ALL CALLERS:

     3  B  V  R     ← CURRENT CODE

  Phonetic:  Three  Bravo  Victor  Romeo

  ████████████████████████████████░░░░░░░░  02:47
  Remaining in this 5-minute window

  FT8/FT4 free text  →  AUTH 3BVR  (paste into WSJT-X or run ft8_bridge)

  ──────────────────────────────────────
  Adjacent windows:   PREV 5MJX   NEXT 4LKP
  ──────────────────────────────────────

  Type a callsign + ENTER to look up their expected code.
  Ctrl+C to exit.
```

> The `.exe` files read the DXpedition callsign and key from
> `dxpedition_config.json`, which must be in the same folder.

### 5 — Distribute the HTML file

Post `station_tool_OH0X.html` on your DXpedition website.
It works fully **offline** — no internet required during operation.

---

## Quick Start — Python

If you prefer running Python scripts directly (or don't need Windows `.exe` files),
the generated Python tools work identically.

### Requirements
- **Python 3.7+** — no `pip install` needed, standard library only
- **Any modern browser** — for the station web tool (offline capable)

### Generate & run

```bash
python generate_tools.py --callsign OH0X --output ./OH0X_tools/
python OH0X_tools/operator_OH0X.py
```

The operator dashboard output is the same as shown above.

---

## FT8 / FT4 / FT2 / Digital Mode Integration

The 4-character auth code fits in the **FT8 free text field** (`AUTH 3BVR` = 9
characters, within the 13-character limit). The free text alphabet
(`A–Z 0–9 + - . / ?`) includes all DLLL characters.

### Automatic WSJT-X integration

```bash
# Windows:
ft8_bridge.exe

# Python:
python OH0X_tools/ft8_bridge_OH0X.py
```

The bridge script:
- **Pushes** the current auth code to WSJT-X free text via UDP (port 2237) automatically
- **Updates** it every 5 minutes when the code rolls over
- **Monitors** incoming decoded messages for the auth code (logs matches)

WSJT-X must have UDP reporting enabled:
*Settings → Reporting → UDP Server: 127.0.0.1:2237*

### Manual method

Paste the code shown in the operator tool into WSJT-X's free text field.
Send it as a standalone free text transmission — for example after `RR73`:

```
CQ       OH0X JP90
OH2LAK   OH0X -12
OH0X     OH2LAK R-08
OH0X     OH2LAK RR73
OH0X     AUTH 3BVR    ← authentication free text
```

### Fox & Hound (DXpedition) mode

In WSJT-X Fox/Hound mode the compound Fox messages use a different message
structure and do not carry free text in the same slot. Options:

1. **Dedicated auth slots**: Send an auth free text message in a dedicated odd or
   even period between QSO batches (the `ft8_bridge` can be configured to inject
   auth transmissions periodically without disrupting the main flow).
2. **Separate sub-band**: Transmit auth codes on a second frequency / VFO-B
   while the main QSO pile-up continues on VFO-A.
3. **Parallel voice announcement**: Announce the code on a separate SSB frequency.

See [SECURITY.md](SECURITY.md) for the full Fox/Hound discussion.

### Station-side auto-verification

The `ft8_bridge` script also works for stations: run it against your own
WSJT-X instance and it will flag any decoded message containing the current
valid auth code from `OH0X`.

---

## Design Principle

**Primary:** The DXpedition authenticates itself to calling stations.
**Secondary:** The DXpedition can optionally verify a calling station's identity.

The pirate problem is solved by the DXpedition proving *it* is real.
Station identity codes are a log-integrity bonus, not the core feature.

### Cryptographic algorithm

```
DXped code  =  DLLL( HMAC-SHA256(secret, "DXPED:OH0X:<5min_window>") )
Station code =  DLLL( HMAC-SHA256(secret, "STATION:OH2LAK:OH0X") )
```

Codes use the **DLLL format**: one digit from `{2-7}` followed by three letters
from `{A-Z}`. No ITU callsign starts with a bare digit, so codes are instantly
distinguishable from callsigns on the air. The alphabet avoids ambiguous
characters (0/O, 1/I/L) and is safe for voice transmission using the NATO
phonetic alphabet.

Verification checks the current window ± 1 (15-minute total tolerance) to
account for clock differences between stations.

---

## Security Model

| What | Protects against | Limitation |
|------|-----------------|------------|
| 5-min DXped time code (DLLL) | Pirate stations, replay attacks | Secret embedded in HTML — extractable by sophisticated adversary |
| Per-callsign station code | Log falsification, callsign spoofing | Same limitation |

**Trust model:** Stations who download `station_tool_OH0X.html` from the
DXpedition's official website inherit the same trust they give to the website.
A pirate cannot produce valid codes without the tool.

**Key rotation:** If the key is compromised mid-DXpedition, regenerate with a
new key and redistribute the HTML. Old codes become invalid immediately.

---

## Files

| File | Who uses it | Share? |
|------|-------------|--------|
| `generate_tools.py` | DXpedition team, once | Yes (this repo) |
| `station_tool_<CALL>.html` | All hams worldwide | **Yes — post publicly** |
| `operator_<CALL>.py` | DXpedition operator desk | **No — keep private** |
| `ft8_bridge_<CALL>.py` | DXpedition operator desk | **No — keep private** |
| `dxpedition_config.json` | Windows .exe tools | **No — contains key** |
| `operator.exe` / `ft8_bridge.exe` | Windows operators | Yes (from Releases) |

Generated files contain embedded keys and are excluded from this repo by
`.gitignore`. Only `generate_tools.py` and the standalone sources are committed.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE)

*73 de the DXpedition Authentication project*
