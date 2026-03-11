# secret-scan-cli

[![npm version](https://badge.fury.io/js/secret-scan-cli.svg)](https://www.npmjs.com/package/secret-scan-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/deps-zero-brightgreen.svg)](https://www.npmjs.com/package/secret-scan-cli)
[![Node.js](https://img.shields.io/badge/node-%3E%3D16-blue.svg)](https://nodejs.org)

> **Zero-dependency CLI to scan your codebase for hardcoded secrets, API keys, and passwords before they leak.**

Detect AWS keys, Stripe keys, GitHub tokens, Slack tokens, database credentials, PEM private keys, and 25+ more patterns — all with zero npm dependencies.

## Install

```bash
npm install -g secret-scan-cli
```

Or run without installing:

```bash
npx secret-scan-cli .
```

## Usage

```bash
# Scan current directory
secret-scan

# Scan a specific path
secret-scan ./src

# CI mode — exit 1 if secrets are found
secret-scan --strict

# Machine-readable JSON output
secret-scan --json

# Only report critical and high findings
secret-scan --min-severity high

# List all 25+ built-in detection rules
secret-scan --list-rules
```

## Example Output

```
Scanning .

Secret Scan Results

src/config.js (2 findings)
  [CRITICAL] AWS Access Key ID
  Line 12:14 — Amazon Web Services access key ID
  Match: AKIA********************...

  [HIGH    ] Slack Webhook URL
  Line 34:20 — Slack incoming webhook URL
  Match: https://hooks.slack.com/...

──────────────────────────────────────────────────
Summary
  Files scanned:       47
  Files with findings: 1
  Total findings:      2

  [CRITICAL] 1
  [HIGH    ] 1
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Scan for secrets
  run: npx secret-scan-cli --strict --min-severity high
```

```bash
# Pre-commit hook
echo "npx secret-scan-cli --strict --json" >> .git/hooks/pre-commit
```

## Detection Rules (25+)

| Severity | Rules |
|----------|-------|
| 🔴 Critical | AWS keys, GitHub tokens, Stripe live keys, OpenAI keys, Anthropic keys, Slack tokens, SendGrid keys, PEM private keys, database connection strings |
| 🟠 High | Google/Firebase API keys, Slack webhooks, Mailgun keys, Basic auth in URLs, Stripe publishable keys |
| 🟡 Medium | Generic password assignments, JWT secrets, API key assignments, Stripe test keys |

## Options

| Flag | Description |
|------|-------------|
| `--strict` | Exit with code 1 if any findings at or above `--min-severity` |
| `--json` | JSON output (secrets redacted, safe for CI logs) |
| `--min-severity <level>` | Filter: `critical`, `high`, `medium`, `low` (default: `medium`) |
| `--list-rules` | Print all built-in detection patterns |
| `--no-color` | Disable ANSI colors |
| `-v, --version` | Show version |
| `-h, --help` | Show help |

## Why zero dependencies?

- **No supply chain risk** — you're scanning for security issues, so the tool itself should be above suspicion
- **Works anywhere** — no `npm install`, just `npx`
- **Auditable** — 100% of the code is in `src/`, readable in 5 minutes

## What it skips

- `node_modules/`, `.git/`, `dist/`, `build/` (configurable)
- Binary files, images, videos
- Common placeholder values (`your-api-key`, `changeme`, `xxxxxxxx`, etc.)

## Part of the 100 Days of AI Hustle

This tool was built by an AI agent as part of the [100 Days of AI Hustle](https://dev.to/alex_mercer) experiment — shipping real tools while learning in public.

## License

MIT © [agent20usd](https://github.com/agent20usd)
