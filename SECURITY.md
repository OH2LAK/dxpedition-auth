# Security Policy

## Threat Model

This project is designed to protect against **casual impersonation** of a
DXpedition station on the amateur radio bands — a problem where pirate stations
mimic a rare callsign to deceive other operators into believing they have made
a genuine contact.

It is **not** designed to protect against nation-state adversaries, nor is it
intended for applications requiring formal cryptographic assurance beyond the
ham radio community context.

## Known Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| HMAC secret embedded in HTML | A determined adversary can extract and forge codes | Acceptable for ham radio threat model; casual pirates cannot easily do this |
| 4-character DLLL code space (6×26×26×26 ≈ 105K) | Brute-force trivial offline, but impractical over the air | Each guess takes seconds on air; 15-minute window limits usefulness |
| Clock skew tolerance ±15 min | Extends the valid window to 45 minutes | Required for practical cross-timezone operation |
| No revocation mechanism | A leaked secret key cannot be invalidated mid-DXpedition | Run `generate_tools.py` with a new key and redistribute |

## Supported Versions

Only the current `main` branch is supported. No version-specific security
patches are provided for older commits.

## Reporting a Vulnerability

If you find a security issue that could meaningfully weaken the protection
against DXpedition impersonation (e.g., a flaw in the HMAC computation,
a bug causing code collisions, or incorrect clock-window handling), please:

1. **Do not open a public GitHub issue.**
2. Open a [GitHub Security Advisory](../../security/advisories/new) in this
   repository (the **Report a vulnerability** button on the Security tab).
3. Include a clear description of the issue and, if possible, a reproducible
   test case.

I will acknowledge the report within 5 days and aim to publish a fix within
30 days, coordinated with you.

## Cryptographic Primitives

| Primitive | Implementation |
|-----------|----------------|
| HMAC | HMAC-SHA256 (Python `hmac` stdlib / Web Crypto API) |
| Key size | 256 bits (32 bytes, random via `secrets.token_bytes`) |
| Encoding | DLLL: digit {2-7} + 3 letters {A-Z} from HMAC digest bytes |
| Time window | 300-second epochs (Unix time ÷ 300, integer division) |

The Python and JavaScript implementations are verified to produce identical
output for identical inputs (see the cross-check in `generate_tools.py`).
