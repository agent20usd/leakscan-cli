#!/usr/bin/env node
'use strict';

const { scan, SECRET_PATTERNS } = require('./index');

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_COLORS = {
  critical: '\x1b[31m', // red
  high: '\x1b[33m',     // yellow
  medium: '\x1b[36m',   // cyan
  low: '\x1b[37m',      // white
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

function parseArgs(argv) {
  const args = argv.slice(2);
  const options = {
    target: '.',
    json: false,
    strict: false,
    minSeverity: 'medium',
    help: false,
    version: false,
    noColor: false,
    patterns: null,
    list: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--json') {
      options.json = true;
    } else if (arg === '--strict') {
      options.strict = true;
    } else if (arg === '--no-color' || arg === '--no-colours') {
      options.noColor = true;
    } else if (arg === '--list-rules') {
      options.list = true;
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--version' || arg === '-v') {
      options.version = true;
    } else if (arg === '--min-severity' && args[i + 1]) {
      options.minSeverity = args[++i].toLowerCase();
    } else if (!arg.startsWith('-')) {
      options.target = arg;
    }
  }

  return options;
}

function printHelp() {
  console.log(`
${BOLD}secret-scan-cli${RESET} — Find hardcoded secrets before they leak

${BOLD}USAGE${RESET}
  secret-scan [path] [options]

${BOLD}ARGUMENTS${RESET}
  path                Directory or file to scan (default: current directory)

${BOLD}OPTIONS${RESET}
  --strict            Exit with code 1 if any secrets found (for CI)
  --json              Output results as JSON
  --min-severity      Minimum severity to report: critical|high|medium|low (default: medium)
  --list-rules        List all built-in detection rules and exit
  --no-color          Disable colored output
  -v, --version       Show version
  -h, --help          Show this help

${BOLD}EXAMPLES${RESET}
  secret-scan                  Scan current directory
  secret-scan ./src            Scan the ./src folder
  secret-scan --strict         Fail in CI if secrets are found
  secret-scan --json           Output machine-readable JSON
  secret-scan --min-severity high    Only report high/critical findings
  secret-scan --list-rules     Show all 25+ detection patterns

${BOLD}SEVERITY LEVELS${RESET}
  critical  Actively exploitable (AWS keys, Stripe live keys, private keys)
  high      Significant risk (Slack tokens, Google API keys, Basic auth in URLs)
  medium    Worth reviewing (generic passwords, JWT secrets, API key assignments)
  low       Informational
  `.trim()
  );
}

function printVersion() {
  const pkg = require('../package.json');
  console.log(pkg.version);
}

function printRules(noColor) {
  const color = (severity, text) => {
    if (noColor) return text;
    return `${SEVERITY_COLORS[severity] || ''}${text}${RESET}`;
  };

  console.log(`\n${BOLD}Built-in Detection Rules${RESET}\n`);
  const grouped = {};
  for (const rule of SECRET_PATTERNS) {
    if (!grouped[rule.severity]) grouped[rule.severity] = [];
    grouped[rule.severity].push(rule);
  }

  const severities = ['critical', 'high', 'medium', 'low'];
  for (const sev of severities) {
    if (!grouped[sev] || grouped[sev].length === 0) continue;
    console.log(`${color(sev, sev.toUpperCase())} (${grouped[sev].length} rules)`);
    for (const rule of grouped[sev]) {
      console.log(`  ${DIM}•${RESET} ${rule.name}`);
      console.log(`    ${DIM}${rule.description}${RESET}`);
    }
    console.log();
  }
  console.log(`Total: ${SECRET_PATTERNS.length} rules`);
}

function formatSeverityBadge(severity, noColor) {
  const upper = severity.toUpperCase().padEnd(8);
  if (noColor) return `[${upper}]`;
  return `${SEVERITY_COLORS[severity] || ''}[${upper}]${RESET}`;
}

function redactMatch(match) {
  if (match.length <= 8) return '*'.repeat(match.length);
  return match.slice(0, 4) + '*'.repeat(Math.min(match.length - 4, 20)) + '...';
}

function printResults(scanResult, options) {
  const { json, noColor, minSeverity, strict } = options;
  const minOrder = SEVERITY_ORDER[minSeverity] ?? SEVERITY_ORDER.medium;

  // Filter results by severity
  const filtered = {
    ...scanResult,
    results: scanResult.results.map(r => ({
      ...r,
      findings: r.findings.filter(f => (SEVERITY_ORDER[f.severity] ?? 99) <= minOrder),
    })).filter(r => r.findings.length > 0 || r.error),
  };
  filtered.totalFindings = filtered.results.reduce((s, r) => s + r.findings.length, 0);
  filtered.filesWithFindings = filtered.results.length;

  if (json) {
    // Redact actual secrets in JSON output
    const safeResults = {
      ...filtered,
      results: filtered.results.map(r => ({
        ...r,
        findings: r.findings.map(f => ({
          ...f,
          match: redactMatch(f.match),
          rawLine: '[redacted]',
        })),
      })),
    };
    console.log(JSON.stringify(safeResults, null, 2));

    if (strict && filtered.totalFindings > 0) process.exit(1);
    return;
  }

  const c = (color, text) => (noColor ? text : `${color}${text}${RESET}`);
  const b = (text) => (noColor ? text : `${BOLD}${text}${RESET}`);

  if (filtered.totalFindings === 0) {
    console.log(`\n${c('\x1b[32m', '✓')} No secrets found in ${scanResult.filesScanned} files.\n`);
    return;
  }

  console.log(`\n${b('Secret Scan Results')}\n`);

  for (const result of filtered.results) {
    if (result.error) {
      console.log(`${c('\x1b[31m', 'ERROR')} ${result.file}: ${result.error}`);
      continue;
    }
    console.log(`${b(result.file)} (${result.findings.length} finding${result.findings.length !== 1 ? 's' : ''})`);

    for (const finding of result.findings) {
      const badge = formatSeverityBadge(finding.severity, noColor);
      console.log(`  ${badge} ${finding.rule}`);
      console.log(`  ${DIM}Line ${finding.line}:${finding.column} — ${finding.description}${RESET}`);
      console.log(`  ${DIM}Match: ${redactMatch(finding.match)}${RESET}`);
      console.log();
    }
  }

  // Summary
  console.log('─'.repeat(50));
  console.log(`${b('Summary')}`);
  console.log(`  Files scanned:       ${scanResult.filesScanned}`);
  console.log(`  Files with findings: ${filtered.filesWithFindings}`);
  console.log(`  Total findings:      ${filtered.totalFindings}`);
  console.log();

  const sev = scanResult.bySeverity;
  if (sev.critical > 0) console.log(`  ${formatSeverityBadge('critical', noColor)} ${sev.critical}`);
  if (sev.high > 0) console.log(`  ${formatSeverityBadge('high', noColor)} ${sev.high}`);
  if (sev.medium > 0) console.log(`  ${formatSeverityBadge('medium', noColor)} ${sev.medium}`);
  if (sev.low > 0) console.log(`  ${formatSeverityBadge('low', noColor)} ${sev.low}`);
  console.log();

  if (strict && filtered.totalFindings > 0) {
    console.log(`${c('\x1b[31m', '✗')} Exiting with code 1 (--strict mode, secrets found)\n`);
    process.exit(1);
  }
}

function main() {
  const options = parseArgs(process.argv);

  if (options.help) {
    printHelp();
    process.exit(0);
  }

  if (options.version) {
    printVersion();
    process.exit(0);
  }

  if (options.list) {
    printRules(options.noColor);
    process.exit(0);
  }

  // Validate target exists
  const fs = require('fs');
  if (!fs.existsSync(options.target)) {
    console.error(`Error: Path not found: ${options.target}`);
    process.exit(2);
  }

  if (!options.json) {
    process.stdout.write(`Scanning ${options.target}...\n`);
  }

  const result = scan({ target: options.target });

  printResults(result, options);
}

main();
