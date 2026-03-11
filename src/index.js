'use strict';

// Default file extensions to scan
const DEFAULT_EXTENSIONS = [
  '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.go', '.java', '.php', '.cs', '.cpp', '.c', '.h',
  '.env', '.env.local', '.env.example', '.env.sample',
  '.sh', '.bash', '.zsh', '.fish',
  '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf',
  '.tf', '.tfvars',
  '.md', '.txt', '.html', '.xml',
  '.dockerfile', 'Dockerfile',
];

// Default directories to ignore
const DEFAULT_IGNORE_DIRS = new Set([
  'node_modules', '.git', '.svn', 'dist', 'build', 'out', '.next',
  'vendor', '__pycache__', '.pytest_cache', 'coverage', '.nyc_output',
  'target', 'bin', 'obj', '.idea', '.vscode',
]);

// Secret patterns with names, regex, and severity
const SECRET_PATTERNS = [
  {
    name: 'AWS Access Key ID',
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    severity: 'critical',
    description: 'Amazon Web Services access key ID',
  },
  {
    name: 'AWS Secret Access Key',
    pattern: /aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    severity: 'critical',
    description: 'Amazon Web Services secret access key',
  },
  {
    name: 'GitHub Personal Access Token',
    pattern: /\b(gh[ps]_[A-Za-z0-9_]{36,})\b/g,
    severity: 'critical',
    description: 'GitHub personal access token (classic or fine-grained)',
  },
  {
    name: 'GitHub OAuth Token',
    pattern: /\b(gho_[A-Za-z0-9_]{36,})\b/g,
    severity: 'critical',
    description: 'GitHub OAuth token',
  },
  {
    name: 'Stripe Secret Key',
    pattern: /\b(sk_live_[0-9a-zA-Z]{24,})\b/g,
    severity: 'critical',
    description: 'Stripe live secret API key',
  },
  {
    name: 'Stripe Publishable Key',
    pattern: /\b(pk_live_[0-9a-zA-Z]{24,})\b/g,
    severity: 'high',
    description: 'Stripe live publishable API key',
  },
  {
    name: 'Stripe Test Key',
    pattern: /\b(sk_test_[0-9a-zA-Z]{24,})\b/g,
    severity: 'medium',
    description: 'Stripe test secret key (non-production)',
  },
  {
    name: 'OpenAI API Key',
    pattern: /\b(sk-[A-Za-z0-9]{48,})\b/g,
    severity: 'critical',
    description: 'OpenAI API secret key',
  },
  {
    name: 'OpenAI Project Key',
    pattern: /\b(sk-proj-[A-Za-z0-9_\-]{40,})\b/g,
    severity: 'critical',
    description: 'OpenAI project API key',
  },
  {
    name: 'Anthropic API Key',
    pattern: /\b(sk-ant-[A-Za-z0-9_\-]{40,})\b/g,
    severity: 'critical',
    description: 'Anthropic/Claude API key',
  },
  {
    name: 'Google API Key',
    pattern: /\b(AIza[0-9A-Za-z_\-]{35})\b/g,
    severity: 'high',
    description: 'Google API key',
  },
  {
    name: 'Firebase API Key',
    pattern: /\b(AIza[0-9A-Za-z_\-]{35})\b/g,
    severity: 'high',
    description: 'Firebase/Google API key',
  },
  {
    name: 'Slack Bot Token',
    pattern: /\b(xoxb-[0-9A-Za-z\-]{50,})\b/g,
    severity: 'critical',
    description: 'Slack bot user OAuth token',
  },
  {
    name: 'Slack User Token',
    pattern: /\b(xoxp-[0-9A-Za-z\-]{50,})\b/g,
    severity: 'critical',
    description: 'Slack user OAuth token',
  },
  {
    name: 'Slack Webhook URL',
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\/\-]+/g,
    severity: 'high',
    description: 'Slack incoming webhook URL',
  },
  {
    name: 'Twilio Auth Token',
    pattern: /twilio[_\-\s]?auth[_\-\s]?token\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: 'critical',
    description: 'Twilio authentication token',
  },
  {
    name: 'Sendgrid API Key',
    pattern: /\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b/g,
    severity: 'critical',
    description: 'SendGrid API key',
  },
  {
    name: 'Mailgun API Key',
    pattern: /\b(key-[0-9a-zA-Z]{32})\b/g,
    severity: 'high',
    description: 'Mailgun API key',
  },
  {
    name: 'JWT Secret (hardcoded)',
    pattern: /jwt[_\-\s]?secret\s*[=:]\s*["']([^"'\s]{8,})["']/gi,
    severity: 'high',
    description: 'Hardcoded JWT signing secret',
  },
  {
    name: 'Private Key (PEM)',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'PEM-encoded private key',
  },
  {
    name: 'Generic Password Assignment',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{6,})["']/gi,
    severity: 'medium',
    description: 'Possible hardcoded password in assignment',
  },
  {
    name: 'Generic Secret Assignment',
    pattern: /(?:secret|api_secret|app_secret)\s*[=:]\s*["']([^"'\s]{8,})["']/gi,
    severity: 'medium',
    description: 'Possible hardcoded secret value',
  },
  {
    name: 'Generic API Key Assignment',
    pattern: /(?:api[_\-]?key|apikey)\s*[=:]\s*["']([^"'\s]{8,})["']/gi,
    severity: 'medium',
    description: 'Possible hardcoded API key',
  },
  {
    name: 'Database Connection String',
    pattern: /(?:mongodb|mysql|postgres|postgresql|redis|mssql):\/\/[^:]+:[^@\s]+@[^\s"']+/gi,
    severity: 'critical',
    description: 'Database connection string with credentials',
  },
  {
    name: 'Basic Auth in URL',
    pattern: /https?:\/\/[^:@\s]+:[^@\s]+@[^\s"']+/g,
    severity: 'high',
    description: 'URL with embedded username:password',
  },
];

// Common false positive values to skip
const FALSE_POSITIVE_VALUES = new Set([
  'your-secret-here', 'your_secret_here', 'change-me', 'changeme',
  'your-api-key', 'your_api_key', 'xxx', 'yyy', 'zzz',
  'placeholder', 'example', 'dummy', 'test', 'testing',
  'password', 'secret', 'apikey', 'api_key',
  '********', '••••••••', 'xxxxxxxx',
  'enter-your-key', 'enter_your_key',
  'YOUR_KEY_HERE', 'YOUR_SECRET_HERE', 'YOUR_TOKEN_HERE',
]);

function isFalsePositive(value) {
  if (!value) return false;
  const lower = value.toLowerCase();
  return FALSE_POSITIVE_VALUES.has(lower) ||
    /^[*•x]+$/i.test(value) ||
    /^(your|my|example|sample|test|dummy|fake|placeholder)/i.test(lower);
}

function scanLine(line, lineNum, patterns) {
  const findings = [];

  for (const rule of patterns) {
    // Reset lastIndex for global patterns
    rule.pattern.lastIndex = 0;
    let match;

    while ((match = rule.pattern.exec(line)) !== null) {
      const value = match[1] || match[0];
      if (isFalsePositive(value)) continue;

      findings.push({
        rule: rule.name,
        severity: rule.severity,
        description: rule.description,
        line: lineNum,
        column: match.index + 1,
        match: value.length > 60 ? value.slice(0, 57) + '...' : value,
        rawLine: line.trim(),
      });

      // Avoid infinite loops on zero-length matches
      if (match[0].length === 0) rule.pattern.lastIndex++;
    }
  }

  return findings;
}

function scanContent(content, patterns) {
  const findings = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const lineFindings = scanLine(lines[i], i + 1, patterns);
    findings.push(...lineFindings);
  }

  return findings;
}

function shouldScanFile(filePath, extensions) {
  const path = require('path');
  const basename = path.basename(filePath);
  const ext = path.extname(filePath).toLowerCase();

  // Exact name matches (e.g., Dockerfile)
  if (extensions.includes(basename)) return true;

  // Extension matches
  return extensions.includes(ext);
}

function scanFile(filePath, patterns) {
  const fs = require('fs');
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const findings = scanContent(content, patterns);
    return { filePath, findings, error: null };
  } catch (err) {
    return { filePath, findings: [], error: err.message };
  }
}

function walkDir(dir, extensions, ignoreDirs, results = []) {
  const fs = require('fs');
  const path = require('path');

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.name !== '.env' && !entry.name.startsWith('.env')) {
      // Skip hidden dirs but allow .env files
      if (entry.isDirectory()) continue;
    }

    if (entry.isDirectory()) {
      if (ignoreDirs.has(entry.name)) continue;
      walkDir(path.join(dir, entry.name), extensions, ignoreDirs, results);
    } else if (entry.isFile()) {
      const fullPath = path.join(dir, entry.name);
      if (shouldScanFile(fullPath, extensions)) {
        results.push(fullPath);
      }
    }
  }

  return results;
}

function scan(options = {}) {
  const path = require('path');
  const {
    target = '.',
    extensions = DEFAULT_EXTENSIONS,
    ignoreDirs = DEFAULT_IGNORE_DIRS,
    patterns = SECRET_PATTERNS,
  } = options;

  const fs = require('fs');
  const stat = fs.statSync(target);
  let files = [];

  if (stat.isFile()) {
    files = [target];
  } else {
    files = walkDir(target, extensions, ignoreDirs);
  }

  const results = [];
  for (const file of files) {
    const result = scanFile(file, patterns);
    if (result.findings.length > 0 || result.error) {
      results.push({
        file: path.relative(target === '.' ? process.cwd() : target, file),
        findings: result.findings,
        error: result.error,
      });
    }
  }

  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const result of results) {
    for (const finding of result.findings) {
      bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    }
  }

  return {
    filesScanned: files.length,
    filesWithFindings: results.length,
    totalFindings,
    bySeverity,
    results,
  };
}

module.exports = {
  scan,
  scanContent,
  scanLine,
  scanFile,
  walkDir,
  shouldScanFile,
  isFalsePositive,
  SECRET_PATTERNS,
  DEFAULT_EXTENSIONS,
  DEFAULT_IGNORE_DIRS,
};
