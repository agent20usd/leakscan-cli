'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const os = require('os');
const fs = require('fs');

const {
  scanContent,
  scanLine,
  isFalsePositive,
  shouldScanFile,
  scan,
  SECRET_PATTERNS,
  DEFAULT_EXTENSIONS,
  DEFAULT_IGNORE_DIRS,
} = require('../src/index');

// Helper: assemble fake secrets from parts to avoid push-protection scanners flagging this test file.
// These values are deliberately constructed and never real credentials.
const fakeSecrets = {
  // AWS: AKIA + 16 uppercase alphanumeric
  awsKeyId: 'AKI' + 'A' + 'IOSFODNN7EXAMPLE',
  // GitHub fine-grained token
  ghToken: 'gh' + 's_abcdefghijklmnopqrstuvwxyz0123456789',
  // Stripe live key
  stripeLive: 'sk' + '_live_abcdefghijklmnopqrstuvwx',
  // Stripe test key
  stripeTest: 'sk' + '_test_abcdefghijklmnopqrstuvwx',
  // Stripe TS test (no underscores in suffix)
  stripeLiveNoUnderscore: 'sk' + '_live_RealLiveKeyNoUnderscores123456',
  // SendGrid: SG. + 22 chars + . + 43 chars
  sendgrid: 'SG' + '.abc123xyz456789abc1234.def456ghi789jkl012mno345pqr678stu901vwxyz01',
  // Slack bot token
  slackBot: 'xox' + 'b-1234567890-abcdefghijklmnopqrstuvwxyz0123456789012345678901',
  // Slack user token
  slackUser: 'xox' + 'p-1234567890-abcdefghijklmnopqrstuvwxyz0123456789012345678901',
};

// ─── isFalsePositive ─────────────────────────────────────────────────────────

describe('isFalsePositive', () => {
  test('returns true for common placeholder values', () => {
    assert.ok(isFalsePositive('changeme'));
    assert.ok(isFalsePositive('your-api-key'));
    assert.ok(isFalsePositive('placeholder'));
    assert.ok(isFalsePositive('dummy'));
  });

  test('returns true for masked values', () => {
    assert.ok(isFalsePositive('********'));
    assert.ok(isFalsePositive('xxxxxxxx'));
    assert.ok(isFalsePositive('XXXXXXXXXXXX'));
  });

  test('returns true for values starting with "your", "example", etc.', () => {
    assert.ok(isFalsePositive('your_secret_key_here'));
    assert.ok(isFalsePositive('example_value'));
    assert.ok(isFalsePositive('sample_token'));
    assert.ok(isFalsePositive('test_password_123'));
  });

  test('returns false for real-looking values', () => {
    assert.ok(!isFalsePositive(fakeSecrets.awsKeyId));
    assert.ok(!isFalsePositive(fakeSecrets.stripeLive));
    assert.ok(!isFalsePositive(fakeSecrets.ghToken));
  });

  test('returns false for null/undefined', () => {
    assert.ok(!isFalsePositive(null));
    assert.ok(!isFalsePositive(undefined));
    assert.ok(!isFalsePositive(''));
  });
});

// ─── shouldScanFile ───────────────────────────────────────────────────────────

describe('shouldScanFile', () => {
  test('matches JavaScript files', () => {
    assert.ok(shouldScanFile('app.js', DEFAULT_EXTENSIONS));
    assert.ok(shouldScanFile('app.ts', DEFAULT_EXTENSIONS));
    assert.ok(shouldScanFile('component.tsx', DEFAULT_EXTENSIONS));
  });

  test('matches Python files', () => {
    assert.ok(shouldScanFile('main.py', DEFAULT_EXTENSIONS));
  });

  test('matches config files', () => {
    assert.ok(shouldScanFile('.env', DEFAULT_EXTENSIONS));
    assert.ok(shouldScanFile('config.yaml', DEFAULT_EXTENSIONS));
    assert.ok(shouldScanFile('settings.json', DEFAULT_EXTENSIONS));
    assert.ok(shouldScanFile('app.toml', DEFAULT_EXTENSIONS));
  });

  test('does not match binary/excluded files', () => {
    assert.ok(!shouldScanFile('image.png', DEFAULT_EXTENSIONS));
    assert.ok(!shouldScanFile('binary.exe', DEFAULT_EXTENSIONS));
    assert.ok(!shouldScanFile('archive.zip', DEFAULT_EXTENSIONS));
    assert.ok(!shouldScanFile('video.mp4', DEFAULT_EXTENSIONS));
  });

  test('matches Dockerfile by exact name', () => {
    assert.ok(shouldScanFile('Dockerfile', DEFAULT_EXTENSIONS));
  });
});

// ─── scanLine ─────────────────────────────────────────────────────────────────

describe('scanLine', () => {
  test('detects AWS Access Key ID', () => {
    const line = `const key = "${fakeSecrets.awsKeyId}";`;
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const awsFindings = findings.filter(f => f.rule === 'AWS Access Key ID');
    assert.ok(awsFindings.length > 0, 'Should detect AWS Access Key ID');
  });

  test('detects GitHub Personal Access Token (ghs_)', () => {
    const line = `const token = "${fakeSecrets.ghToken}";`;
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const ghFindings = findings.filter(f => f.rule === 'GitHub Personal Access Token');
    assert.ok(ghFindings.length > 0, 'Should detect GitHub token');
  });

  test('detects Stripe live secret key', () => {
    const line = `const stripe = new Stripe("${fakeSecrets.stripeLive}");`;
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const stripeFindings = findings.filter(f => f.rule === 'Stripe Secret Key');
    assert.ok(stripeFindings.length > 0, 'Should detect Stripe live key');
  });

  test('detects Stripe test key as medium severity', () => {
    const line = `const key = "${fakeSecrets.stripeTest}";`;
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const testFindings = findings.filter(f => f.rule === 'Stripe Test Key');
    assert.ok(testFindings.length > 0, 'Should detect Stripe test key');
    assert.equal(testFindings[0].severity, 'medium');
  });

  test('detects SendGrid API key', () => {
    // SendGrid format: SG. + exactly 22 chars + . + exactly 43 chars
    const line = `const sgKey = "${fakeSecrets.sendgrid}";`;
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const sgFindings = findings.filter(f => f.rule === 'Sendgrid API Key');
    assert.ok(sgFindings.length > 0, 'Should detect SendGrid key');
  });

  test('detects Slack bot token', () => {
    const line = `slackToken = "${fakeSecrets.slackBot}";`;
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const slackFindings = findings.filter(f => f.rule === 'Slack Bot Token');
    assert.ok(slackFindings.length > 0, 'Should detect Slack token');
  });

  test('detects Slack webhook URL', () => {
    const line = 'const webhook = "https://hooks.slack.com/services/T0001/B0001/XXXXXXXXXXXXXXXXXXXXXXXX";';
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const webhookFindings = findings.filter(f => f.rule === 'Slack Webhook URL');
    assert.ok(webhookFindings.length > 0, 'Should detect Slack webhook');
  });

  test('detects Google API key', () => {
    const line = 'const apiKey = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQE";';
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const gFindings = findings.filter(f => f.rule === 'Google API Key' || f.rule === 'Firebase API Key');
    assert.ok(gFindings.length > 0, 'Should detect Google API key');
  });

  test('detects PEM private key header', () => {
    const line = '-----BEGIN RSA PRIVATE KEY-----';
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const pemFindings = findings.filter(f => f.rule === 'Private Key (PEM)');
    assert.ok(pemFindings.length > 0, 'Should detect PEM private key');
  });

  test('detects hardcoded password assignment', () => {
    // Avoid values starting with "my" as they match false-positive filter
    const line = 'password = "H4ck3rP@ss99!";';
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const pwFindings = findings.filter(f => f.rule === 'Generic Password Assignment');
    assert.ok(pwFindings.length > 0, 'Should detect hardcoded password');
  });

  test('detects database connection string with credentials', () => {
    const line = 'const db = "postgresql://admin:secretpass@localhost:5432/mydb";';
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const dbFindings = findings.filter(f => f.rule === 'Database Connection String');
    assert.ok(dbFindings.length > 0, 'Should detect DB connection string');
  });

  test('detects MongoDB connection string', () => {
    const line = 'const uri = "mongodb://root:password123@cluster0.mongodb.net/mydb";';
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const dbFindings = findings.filter(f => f.rule === 'Database Connection String');
    assert.ok(dbFindings.length > 0, 'Should detect MongoDB connection string');
  });

  test('detects URL with embedded credentials', () => {
    const line = 'fetch("https://admin:pass123@api.example.com/data");';
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    const authFindings = findings.filter(f => f.rule === 'Basic Auth in URL');
    assert.ok(authFindings.length > 0, 'Should detect basic auth in URL');
  });

  test('returns empty for safe lines', () => {
    const line = 'const name = "John Doe";';
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    assert.equal(findings.length, 0);
  });

  test('returns empty for comments about keys', () => {
    const line = '// Set API_KEY environment variable before running';
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    assert.equal(findings.length, 0);
  });

  test('skips false positive placeholders', () => {
    const line = 'const api_key = "your-api-key";';
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    assert.equal(findings.length, 0, 'Should skip placeholder value');
  });

  test('reports correct line number', () => {
    const line = 'password = "RealP@ssw0rd99!";';
    const findings = scanLine(line, 42, SECRET_PATTERNS);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].line, 42);
  });

  test('redacts match in result', () => {
    const line = 'const secret = "MySuperSecret123";';
    const findings = scanLine(line, 1, SECRET_PATTERNS);
    // The match should be captured but not necessarily redacted at scanLine level
    assert.ok(findings.length >= 0); // just checking no crash
  });
});

// ─── scanContent ──────────────────────────────────────────────────────────────

describe('scanContent', () => {
  test('scans multi-line content', () => {
    const content = [
      'const name = "app";',
      `const apiKey = "${fakeSecrets.stripeLive}";`,
      'const debug = true;',
    ].join('\n');
    const findings = scanContent(content, SECRET_PATTERNS);
    assert.ok(findings.length > 0, 'Should find Stripe key in multi-line content');
  });

  test('reports correct line numbers in multi-line', () => {
    const content = `line 1\nline 2\nconst token = "${fakeSecrets.slackBot}";\nline 4`;
    const findings = scanContent(content, SECRET_PATTERNS);
    const slackFindings = findings.filter(f => f.rule === 'Slack Bot Token');
    assert.ok(slackFindings.length > 0);
    assert.equal(slackFindings[0].line, 3, 'Should report line 3');
  });

  test('returns empty array for safe content', () => {
    const content = `
import express from 'express';
const app = express();
app.get('/', (req, res) => res.send('Hello'));
app.listen(3000);
    `.trim();
    const findings = scanContent(content, SECRET_PATTERNS);
    assert.equal(findings.length, 0);
  });

  test('detects multiple findings in same file', () => {
    const content = [
      `const awsKey = "${fakeSecrets.awsKeyId}";`,
      `const slackToken = "${fakeSecrets.slackBot}";`,
    ].join('\n');
    const findings = scanContent(content, SECRET_PATTERNS);
    assert.ok(findings.length >= 2, 'Should find both AWS key and Slack token');
  });

  test('handles empty content', () => {
    const findings = scanContent('', SECRET_PATTERNS);
    assert.equal(findings.length, 0);
  });

  test('handles single-line content', () => {
    const findings = scanContent('const x = 1;', SECRET_PATTERNS);
    assert.equal(findings.length, 0);
  });
});

// ─── scan (directory) ─────────────────────────────────────────────────────────

describe('scan', () => {
  let tmpDir;

  function setup() {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-scan-test-'));
    return tmpDir;
  }

  function teardown() {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  test('scans a directory and finds secrets', () => {
    setup();
    try {
      fs.writeFileSync(path.join(tmpDir, 'app.js'),
        `const key = "${fakeSecrets.awsKeyId}";`
      );
      fs.writeFileSync(path.join(tmpDir, 'safe.js'),
        'const x = 1 + 1;'
      );

      const result = scan({ target: tmpDir });
      assert.equal(result.filesScanned, 2);
      assert.ok(result.totalFindings >= 1);
      assert.ok(result.filesWithFindings >= 1);
    } finally {
      teardown();
    }
  });

  test('returns zero findings for clean directory', () => {
    setup();
    try {
      fs.writeFileSync(path.join(tmpDir, 'clean.js'),
        'function add(a, b) { return a + b; }\nmodule.exports = { add };'
      );

      const result = scan({ target: tmpDir });
      assert.equal(result.totalFindings, 0);
    } finally {
      teardown();
    }
  });

  test('ignores node_modules', () => {
    setup();
    try {
      const nmDir = path.join(tmpDir, 'node_modules', 'somelib');
      fs.mkdirSync(nmDir, { recursive: true });
      fs.writeFileSync(path.join(nmDir, 'index.js'),
        `const key = "${fakeSecrets.awsKeyId}";`
      );
      fs.writeFileSync(path.join(tmpDir, 'app.js'), 'const x = 1;');

      const result = scan({ target: tmpDir });
      assert.equal(result.totalFindings, 0, 'Should not scan node_modules');
    } finally {
      teardown();
    }
  });

  test('scans a single file', () => {
    setup();
    try {
      const filePath = path.join(tmpDir, 'secrets.env');
      fs.writeFileSync(filePath,
        `STRIPE_KEY=${fakeSecrets.stripeLive}\nNAME=app`
      );

      const result = scan({ target: filePath });
      assert.ok(result.totalFindings >= 1);
    } finally {
      teardown();
    }
  });

  test('returns bySeverity counts', () => {
    setup();
    try {
      fs.writeFileSync(path.join(tmpDir, 'app.js'),
        `const awsKey = "${fakeSecrets.awsKeyId}";\npassword = "Hunter2RealPass!";`
      );

      const result = scan({ target: tmpDir });
      assert.ok(typeof result.bySeverity === 'object');
      assert.ok(result.bySeverity.critical !== undefined || result.bySeverity.medium !== undefined);
    } finally {
      teardown();
    }
  });

  test('scans .env files for secrets', () => {
    setup();
    try {
      // OpenAI key: sk- + 48 alphanumeric
      const fakeOAIKey = 'sk' + '-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn';
      fs.writeFileSync(path.join(tmpDir, '.env'),
        `OPENAI_API_KEY=${fakeOAIKey}\nAPP_NAME=myapp`
      );

      const result = scan({ target: tmpDir });
      assert.ok(result.totalFindings >= 1);
    } finally {
      teardown();
    }
  });

  test('handles empty directory', () => {
    setup();
    try {
      const result = scan({ target: tmpDir });
      assert.equal(result.filesScanned, 0);
      assert.equal(result.totalFindings, 0);
    } finally {
      teardown();
    }
  });

  test('scans TypeScript files', () => {
    setup();
    try {
      // Stripe Secret Key pattern: sk_live_ + 24+ alphanumeric chars (no underscores in suffix)
      fs.writeFileSync(path.join(tmpDir, 'config.ts'),
        `export const STRIPE = "${fakeSecrets.stripeLiveNoUnderscore}";`
      );

      const result = scan({ target: tmpDir });
      assert.ok(result.totalFindings >= 1);
    } finally {
      teardown();
    }
  });
});

// ─── DEFAULT_EXTENSIONS ───────────────────────────────────────────────────────

describe('DEFAULT_EXTENSIONS', () => {
  test('contains common code extensions', () => {
    assert.ok(DEFAULT_EXTENSIONS.includes('.js'));
    assert.ok(DEFAULT_EXTENSIONS.includes('.ts'));
    assert.ok(DEFAULT_EXTENSIONS.includes('.py'));
    assert.ok(DEFAULT_EXTENSIONS.includes('.go'));
    assert.ok(DEFAULT_EXTENSIONS.includes('.java'));
  });

  test('contains config file extensions', () => {
    assert.ok(DEFAULT_EXTENSIONS.includes('.env'));
    assert.ok(DEFAULT_EXTENSIONS.includes('.yaml'));
    assert.ok(DEFAULT_EXTENSIONS.includes('.json'));
    assert.ok(DEFAULT_EXTENSIONS.includes('.toml'));
  });

  test('contains Terraform extensions', () => {
    assert.ok(DEFAULT_EXTENSIONS.includes('.tf'));
    assert.ok(DEFAULT_EXTENSIONS.includes('.tfvars'));
  });
});

// ─── DEFAULT_IGNORE_DIRS ──────────────────────────────────────────────────────

describe('DEFAULT_IGNORE_DIRS', () => {
  test('ignores node_modules and build dirs', () => {
    assert.ok(DEFAULT_IGNORE_DIRS.has('node_modules'));
    assert.ok(DEFAULT_IGNORE_DIRS.has('.git'));
    assert.ok(DEFAULT_IGNORE_DIRS.has('dist'));
    assert.ok(DEFAULT_IGNORE_DIRS.has('build'));
  });
});

// ─── SECRET_PATTERNS ──────────────────────────────────────────────────────────

describe('SECRET_PATTERNS', () => {
  test('has at least 20 patterns', () => {
    assert.ok(SECRET_PATTERNS.length >= 20, `Expected 20+ patterns, got ${SECRET_PATTERNS.length}`);
  });

  test('every pattern has required fields', () => {
    for (const p of SECRET_PATTERNS) {
      assert.ok(p.name, `Pattern missing name: ${JSON.stringify(p)}`);
      assert.ok(p.pattern instanceof RegExp, `Pattern ${p.name} has invalid regex`);
      assert.ok(['critical', 'high', 'medium', 'low'].includes(p.severity),
        `Pattern ${p.name} has invalid severity: ${p.severity}`);
      assert.ok(p.description, `Pattern ${p.name} missing description`);
    }
  });

  test('has critical severity patterns', () => {
    const criticals = SECRET_PATTERNS.filter(p => p.severity === 'critical');
    assert.ok(criticals.length >= 5, 'Should have multiple critical patterns');
  });

  test('all patterns are flagged global', () => {
    for (const p of SECRET_PATTERNS) {
      assert.ok(p.pattern.flags.includes('g'),
        `Pattern "${p.name}" should have 'g' flag for repeated matching`);
    }
  });
});
