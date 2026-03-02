# Contributing

Thank you for your interest in improving the DXpedition Authentication System!
Bug reports, ideas, and pull requests are all welcome.

## Getting Started

```bash
git clone https://github.com/YOUR_USERNAME/dxpedition-auth.git
cd dxpedition-auth
python generate_tools.py --callsign TEST --output ./test_output/
```

No dependencies to install — the project uses Python standard library only.

## What to Work On

Check the [Issues](../../issues) tab for open items. Good first issues are
labelled `good first issue`.

Areas that would benefit from contributions:

- **Portability** — testing the operator tool on Windows (the curses-based
  input currently uses POSIX `termios`; a Windows-compatible fallback would help)
- **Accessibility** — improving the web tool for screen readers and keyboard-only use
- **Internationalisation** — translating the web tool UI
- **Testing** — adding a test suite (`test_crypto.py`) that cross-validates
  Python and JavaScript HMAC/Base32 output using known test vectors
- **Documentation** — improving the operating procedure for non-technical hams

## Pull Request Guidelines

1. **Keep changes focused.** One logical change per PR.
2. **Test your change.** Run `generate_tools.py` with a test callsign and verify
   the station HTML and operator tool still work correctly.
3. **Do not break the crypto contract.** The Python and JavaScript implementations
   must always produce identical output for identical inputs. If you change either,
   add a comment explaining how you verified they still match.
4. **No new runtime dependencies.** The project intentionally has zero pip
   requirements. If you feel a dependency is truly necessary, raise an issue first.
5. **Never commit generated files.** `station_tool_*.html` and `operator_*.py`
   contain embedded keys and are in `.gitignore` for a reason.

## Commit Style

```
Short imperative summary (≤72 chars)

Optional body explaining the why, not the what. Wrap at 72 chars.
```

Examples:
- `Fix base32 encoding edge case for single-byte input`
- `Add Windows fallback for operator tool input loop`
- `Improve verify panel UX: show phonetic of entered code`

## Code Style

- Python: follow PEP 8, prefer clarity over cleverness.
- JavaScript: vanilla ES2017+, no frameworks, no build steps.
- HTML/CSS: keep it self-contained in the template string inside `generate_tools.py`.

## Questions

Open a [Discussion](../../discussions) for questions, ideas, or to share a
successful DXpedition where this tool was used. 73!
