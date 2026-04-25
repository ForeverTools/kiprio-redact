# kiprio-redact

[![PyPI](https://img.shields.io/pypi/v/kiprio-redact.svg)](https://pypi.org/project/kiprio-redact/)
[![Python](https://img.shields.io/pypi/pyversions/kiprio-redact.svg)](https://pypi.org/project/kiprio-redact/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Local, offline PII redaction in one pipe.** Single-file Python CLI. No telemetry, no network calls.

```sh
pip install kiprio-redact
echo "ping me at hi@example.com or +44 7700 900123" | kiprio-redact
# ping me at [REDACTED] or [REDACTED]
```

## What it redacts

`email`, `phone`, `iban`, `card` (Luhn-validated), `nino` (UK National Insurance, prefix-validated), `uuid`, `jwt`, `ip` (v4 + v6).

## Usage

```sh
# default: redact every supported type, write to stdout
kiprio-redact < input.txt

# pick types
kiprio-redact -t email,phone,card < input.txt

# mask each char with X (preserves length)
echo "card 4111 1111 1111 1111" | kiprio-redact -m X
# card XXXXXXXXXXXXXXXXXXX

# custom replacement
kiprio-redact -r "<pii>" < input.txt

# structured findings (JSON) instead of redacted text
kiprio-redact --json < input.txt

# files in/out
kiprio-redact -i in.log -o redacted.log

# verbose: count by type to stderr
kiprio-redact -v < big.log > /dev/null
# kiprio-redact: card=2, email=14, ip=3, phone=7 (total=26)
```

Library use:

```python
from kiprio_redact import redact, find_spans

text = "alice@example.com 4111 1111 1111 1111"
clean, findings = redact(text)
# clean    = "[REDACTED] [REDACTED]"
# findings = [{"type":"email","start":0,"end":17,"raw":"alice@example.com"},
#             {"type":"card","start":18,"end":37,"raw":"4111 1111 1111 1111"}]
```

## CLI vs API — when to use which

| Use case                              | CLI (`kiprio-redact`)            | API ([`/v1/redact`](https://kiprio.com/v1/redact/?utm_source=pypi&utm_medium=cli&utm_campaign=kiprio-redact)) |
| ------------------------------------- | -------------------------------- | ------------------------------------------------ |
| One-off log scrub, dev pipeline       | ✅                               | overkill                                         |
| Offline, no data leaves your box      | ✅                               | —                                                |
| Free / unlimited                      | ✅                               | usage-billed                                     |
| Context-aware (names, addresses, ORG) | regex only                       | ✅ NER + LLM-assisted                            |
| URLs, custom dictionaries, postcodes  | regex subset                     | ✅ extended catalogue                            |
| Higher recall on edge cases           | —                                | ✅                                               |
| Managed: SLA, audit trail, billing    | —                                | ✅                                               |

The CLI uses the same regex muscles that power the API's regex layer, so a finding here is a finding there. The API adds context-aware detection on top.

## Exit codes

| Code | Meaning                                |
| ---- | -------------------------------------- |
| 0    | Success                                |
| 2    | Bad arguments (unknown type, etc.)     |

## Privacy

`kiprio-redact` makes **zero network calls** and writes nothing to disk except the output you ask for. Read [`kiprio_redact/__init__.py`](kiprio_redact/__init__.py) — under 250 LOC, all stdlib.

## License

MIT — see [LICENSE](LICENSE).
