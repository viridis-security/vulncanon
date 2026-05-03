#!/usr/bin/env node
/**
 * vulnc — VulnCanon security compiler.
 *
 * Validates that an entry in canon/vulncanon/entries/ is a *compiled artifact*,
 * not a prose hypothesis. The central axiom this enforces:
 *
 *   No proof, no payout. No compile, no canon. No mitigation, no merge.
 *
 * For v1 the proof is fixture-based: vulnerable_fixture/ must demonstrate the
 * invariant violation (test FAILS), patched_fixture/ must demonstrate the fix
 * (test PASSES). Lean theorems are an optional Phase-2 layer.
 *
 * Usage:
 *   vulnc check <entry-dir>
 *   vulnc check-all [canon-root]
 *   vulnc scan <target-dir> [--canon <canon-root>] [--json]
 *   vulnc --help
 *
 * Zero external dependencies. Node >=18.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const VULNC_VERSION = '0.1.0';
const ENTRY_FILE = 'entry.json';
const SCHEMA_REL_PATH = '../../../schemas/vulnerability.schema.json';
const REPORT_REL_PATH = '../../../reports';

// ---------- color helpers (no deps) ----------
const isTTY = process.stdout.isTTY;
const c = {
  green: (s) => isTTY ? `\x1b[32m${s}\x1b[0m` : s,
  red:   (s) => isTTY ? `\x1b[31m${s}\x1b[0m` : s,
  yellow:(s) => isTTY ? `\x1b[33m${s}\x1b[0m` : s,
  cyan:  (s) => isTTY ? `\x1b[36m${s}\x1b[0m` : s,
  bold:  (s) => isTTY ? `\x1b[1m${s}\x1b[0m`  : s,
  dim:   (s) => isTTY ? `\x1b[2m${s}\x1b[0m`  : s,
};

// ---------- minimal JSON-Schema validator (subset sufficient for our schemas) ----------
function validateSchema(instance, schema, pathStr = '$') {
  const errors = [];

  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual = Array.isArray(instance) ? 'array'
      : instance === null ? 'null'
      : typeof instance;
    if (!types.includes(actual)) {
      errors.push(`${pathStr}: expected type ${types.join('|')}, got ${actual}`);
      return errors;
    }
  }

  if (schema.const !== undefined && instance !== schema.const) {
    errors.push(`${pathStr}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(instance)}`);
  }

  if (schema.enum && !schema.enum.includes(instance)) {
    errors.push(`${pathStr}: value ${JSON.stringify(instance)} not in enum [${schema.enum.map(JSON.stringify).join(', ')}]`);
  }

  if (schema.pattern && typeof instance === 'string') {
    if (!new RegExp(schema.pattern).test(instance)) {
      errors.push(`${pathStr}: string ${JSON.stringify(instance)} does not match pattern /${schema.pattern}/`);
    }
  }

  if (typeof instance === 'string') {
    if (schema.minLength != null && instance.length < schema.minLength)
      errors.push(`${pathStr}: string length ${instance.length} < minLength ${schema.minLength}`);
    if (schema.maxLength != null && instance.length > schema.maxLength)
      errors.push(`${pathStr}: string length ${instance.length} > maxLength ${schema.maxLength}`);
  }

  if (instance && typeof instance === 'object' && !Array.isArray(instance)) {
    if (schema.required) {
      for (const key of schema.required) {
        if (!(key in instance)) {
          errors.push(`${pathStr}: missing required property "${key}"`);
        }
      }
    }
    if (schema.additionalProperties === false && schema.properties) {
      for (const key of Object.keys(instance)) {
        if (!(key in schema.properties)) {
          errors.push(`${pathStr}: unexpected property "${key}"`);
        }
      }
    }
    if (schema.properties) {
      for (const [key, subSchema] of Object.entries(schema.properties)) {
        if (key in instance) {
          errors.push(...validateSchema(instance[key], subSchema, `${pathStr}.${key}`));
        }
      }
    }
    if (schema.minProperties != null && Object.keys(instance).length < schema.minProperties) {
      errors.push(`${pathStr}: object has fewer than ${schema.minProperties} properties`);
    }
    if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
      const declared = new Set(Object.keys(schema.properties || {}));
      for (const [key, val] of Object.entries(instance)) {
        if (!declared.has(key)) {
          errors.push(...validateSchema(val, schema.additionalProperties, `${pathStr}.${key}`));
        }
      }
    }
  }

  if (Array.isArray(instance) && schema.items) {
    instance.forEach((item, i) => {
      errors.push(...validateSchema(item, schema.items, `${pathStr}[${i}]`));
    });
  }

  return errors;
}

// ---------- check helpers ----------
function pass(message, details) { return { status: 'pass', message, ...(details && { details }) }; }
function fail(message, details) { return { status: 'fail', message, ...(details && { details }) }; }
function skip(message, details) { return { status: 'skipped', message, ...(details && { details }) }; }

// ---------- individual checks ----------
function checkSchema(entry, schema) {
  const errors = validateSchema(entry, schema);
  return errors.length === 0
    ? pass('entry.json conforms to vulnerability schema')
    : fail(`entry.json has ${errors.length} schema violation(s)`, errors);
}

function checkStructure(entryDir) {
  const required = [
    'entry.json',
    'README.md',
    'mitigation.md',
    'rule.semgrep.yml',
    'vulnerable_fixture',
    'patched_fixture',
    'vulnerable_fixture/exploit.test.js',
    'patched_fixture/exploit.test.js',
  ];
  const missing = required.filter((p) => !fs.existsSync(path.join(entryDir, p)));
  return missing.length === 0
    ? pass('all required artifacts present')
    : fail('missing required artifacts', missing);
}

function runFixture(fixtureDir) {
  // We treat the fixture as a self-contained Node test that exits 0 on
  // invariant-holds, non-zero on invariant-violation. This is the *test*
  // that proves the entry is not a hypothesis: the vulnerable fixture must
  // exit non-zero (the assertion catches the violation), the patched
  // fixture must exit zero (the fix holds).
  const result = spawnSync('node', ['exploit.test.js'], {
    cwd: fixtureDir,
    encoding: 'utf8',
    timeout: 15000,
  });
  return {
    exitCode: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error ? result.error.message : null,
  };
}

function checkVulnerableFixtureFails(entryDir) {
  const r = runFixture(path.join(entryDir, 'vulnerable_fixture'));
  if (r.error) return fail(`vulnerable fixture errored: ${r.error}`);
  if (r.exitCode === 0) {
    return fail(
      'vulnerable_fixture/exploit.test.js exited 0 — the invariant did NOT fail. ' +
      'A vulnerable fixture MUST demonstrate a real invariant violation.',
      { stdout: r.stdout, stderr: r.stderr }
    );
  }
  return pass(`vulnerable fixture failed (exit ${r.exitCode}) — invariant violation demonstrated`,
    { exitCode: r.exitCode, stdoutTail: r.stdout.slice(-300) });
}

function checkPatchedFixturePasses(entryDir) {
  const r = runFixture(path.join(entryDir, 'patched_fixture'));
  if (r.error) return fail(`patched fixture errored: ${r.error}`);
  if (r.exitCode !== 0) {
    return fail(
      `patched_fixture/exploit.test.js exited ${r.exitCode} — the fix does NOT hold. ` +
      'The patched fixture MUST exit 0 (invariant satisfied).',
      { stdout: r.stdout, stderr: r.stderr }
    );
  }
  return pass('patched fixture passed (exit 0) — invariant restored',
    { stdoutTail: r.stdout.slice(-300) });
}

function checkStaticRuleValid(entryDir) {
  const rulePath = path.join(entryDir, 'rule.semgrep.yml');
  let content;
  try { content = fs.readFileSync(rulePath, 'utf8'); }
  catch (e) { return fail(`could not read ${rulePath}: ${e.message}`); }

  if (content.trim().length === 0) return fail('rule.semgrep.yml is empty');
  if (!/^\s*rules\s*:/m.test(content))
    return fail('rule.semgrep.yml: missing top-level "rules:" key');
  if (!/^\s*-\s*id\s*:/m.test(content))
    return fail('rule.semgrep.yml: no rule id found (expected "- id:")');

  // Optional: actually run semgrep if present.
  const semgrep = spawnSync('semgrep', ['--validate', '--config', rulePath],
    { encoding: 'utf8' });
  if (semgrep.error && semgrep.error.code === 'ENOENT') {
    return pass('rule.semgrep.yml is structurally valid (semgrep CLI not installed — full validate skipped)');
  }
  if (semgrep.status === 0) {
    return pass('rule.semgrep.yml validated by semgrep --validate');
  }
  return fail('semgrep --validate rejected rule.semgrep.yml',
    { stdout: semgrep.stdout, stderr: semgrep.stderr });
}

function checkMitigationPresent(entryDir) {
  const mp = path.join(entryDir, 'mitigation.md');
  let content;
  try { content = fs.readFileSync(mp, 'utf8'); }
  catch (e) { return fail(`could not read mitigation.md: ${e.message}`); }
  if (content.trim().length < 80)
    return fail('mitigation.md is too short (<80 chars). Mitigation must be substantive.');
  return pass(`mitigation.md present (${content.length} chars)`);
}

function checkDuplicate(entry, canonRoot) {
  // A duplicate would be any other entry with the same id or with a near-
  // identical claim+invariant pair. v1 only checks id collisions.
  const entriesDir = path.join(canonRoot, 'entries');
  if (!fs.existsSync(entriesDir)) return skip('no entries/ directory');
  const dupes = [];
  for (const dir of fs.readdirSync(entriesDir)) {
    const candidate = path.join(entriesDir, dir, 'entry.json');
    if (!fs.existsSync(candidate)) continue;
    if (dir === entry.id) continue; // self
    try {
      const other = JSON.parse(fs.readFileSync(candidate, 'utf8'));
      if (other.id === entry.id) dupes.push(dir);
    } catch { /* skip malformed */ }
  }
  return dupes.length === 0
    ? pass('no duplicate ids found in canon')
    : fail('duplicate id collision', dupes);
}

function checkSafety(entryDir) {
  // Defensive: scan the entry tree for forbidden patterns. We are a *defensive*
  // canon — fixtures must be self-contained and safe. Any sign of live-target
  // exploitation, exfiltration, or destructive automation rejects the entry.
  const FORBIDDEN = [
    /curl\s+https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
    /\bwget\s+https?:\/\//i,
    /\brm\s+-rf\s+\//i,
    /\bnc\s+-e\b/i,
    /\b(reverse|bind)[\s_-]?shell\b/i,
    /eval\(\s*atob\(/i,
    /child_process[\s\S]{0,40}\b(curl|wget|bash\s+-c)/i,
  ];
  const violations = [];
  function walk(dir) {
    for (const name of fs.readdirSync(dir)) {
      const full = path.join(dir, name);
      const stat = fs.statSync(full);
      if (stat.isDirectory()) { walk(full); continue; }
      if (stat.size > 200_000) continue;
      let text;
      try { text = fs.readFileSync(full, 'utf8'); } catch { continue; }
      for (const pat of FORBIDDEN) {
        if (pat.test(text)) {
          violations.push({ file: path.relative(entryDir, full), pattern: pat.toString() });
        }
      }
    }
  }
  walk(entryDir);
  return violations.length === 0
    ? pass('safety scan clean — no forbidden patterns found')
    : fail('safety scan found forbidden patterns', violations);
}

// ---------- the main check ----------
function checkEntry(entryDir, canonRoot, schema) {
  const startedAt = new Date().toISOString();
  const entryJsonPath = path.join(entryDir, ENTRY_FILE);

  if (!fs.existsSync(entryJsonPath)) {
    return {
      vulnc_version: VULNC_VERSION,
      entry_id: '<unknown>',
      entry_path: entryDir,
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      overall_status: 'error',
      checks: {
        schema: fail(`${ENTRY_FILE} not found in ${entryDir}`),
        structure: fail('cannot run structure check without entry.json'),
        vulnerable_fixture_fails: skip('precondition failed'),
        patched_fixture_passes: skip('precondition failed'),
        static_rule_valid: skip('precondition failed'),
        mitigation_present: skip('precondition failed'),
        duplicate_check: skip('precondition failed'),
        safety_scan: skip('precondition failed'),
      },
    };
  }

  let entry;
  try { entry = JSON.parse(fs.readFileSync(entryJsonPath, 'utf8')); }
  catch (e) {
    return {
      vulnc_version: VULNC_VERSION,
      entry_id: '<unparseable>',
      entry_path: entryDir,
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      overall_status: 'error',
      checks: {
        schema: fail(`entry.json is not valid JSON: ${e.message}`),
        structure: skip('precondition failed'),
        vulnerable_fixture_fails: skip('precondition failed'),
        patched_fixture_passes: skip('precondition failed'),
        static_rule_valid: skip('precondition failed'),
        mitigation_present: skip('precondition failed'),
        duplicate_check: skip('precondition failed'),
        safety_scan: skip('precondition failed'),
      },
    };
  }

  const checks = {
    schema:                   checkSchema(entry, schema),
    structure:                checkStructure(entryDir),
    vulnerable_fixture_fails: checkVulnerableFixtureFails(entryDir),
    patched_fixture_passes:   checkPatchedFixturePasses(entryDir),
    static_rule_valid:        checkStaticRuleValid(entryDir),
    mitigation_present:       checkMitigationPresent(entryDir),
    duplicate_check:          checkDuplicate(entry, canonRoot),
    safety_scan:              checkSafety(entryDir),
  };

  // Lean is optional for v1 — only run if mode requests it AND theorem.lean exists.
  if (entry.evidence && /lean/.test(entry.evidence.mode || '')) {
    const leanPath = path.join(entryDir, entry.evidence.lean_file || 'theorem.lean');
    checks.lean_compiles = fs.existsSync(leanPath)
      ? skip('lean check requested but Aristotle/lake integration is Phase 2')
      : fail(`evidence mode "${entry.evidence.mode}" requires theorem.lean but file not found`);
  }

  const failedAny = Object.values(checks).some((c) => c.status === 'fail' || c.status === 'error');
  const overall_status = failedAny ? 'rejected' : 'accepted';

  return {
    vulnc_version: VULNC_VERSION,
    entry_id: entry.id,
    entry_path: entryDir,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    overall_status,
    checks,
  };
}

function loadSchema() {
  const schemaPath = path.resolve(__dirname, SCHEMA_REL_PATH);
  return JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
}

function findCanonRoot(entryDir) {
  // Walk up until we find a directory containing schemas/vulnerability.schema.json
  let cur = path.resolve(entryDir);
  while (cur !== path.dirname(cur)) {
    if (fs.existsSync(path.join(cur, 'schemas', 'vulnerability.schema.json'))) return cur;
    cur = path.dirname(cur);
  }
  // Fallback to two levels above the compiler dir.
  return path.resolve(__dirname, '../../..');
}

function writeReport(report) {
  const canonRoot = findCanonRoot(report.entry_path);
  const reportsDir = path.join(canonRoot, 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });
  const safeId = report.entry_id.replace(/[^A-Za-z0-9_-]/g, '_');
  const out = path.join(reportsDir, `${safeId}.compile-report.json`);
  fs.writeFileSync(out, JSON.stringify(report, null, 2) + '\n');
  return out;
}

function printReport(report) {
  const banner = report.overall_status === 'accepted'
    ? c.green(c.bold('CANON STATUS: ACCEPTED'))
    : c.red(c.bold('CANON STATUS: REJECTED'));

  console.log('');
  console.log(c.cyan(c.bold(`vulnc v${VULNC_VERSION}  ·  ${report.entry_id}`)));
  console.log(c.dim(report.entry_path));
  console.log('');
  for (const [name, check] of Object.entries(report.checks)) {
    const icon =
      check.status === 'pass'    ? c.green('  pass    ') :
      check.status === 'fail'    ? c.red('  fail    ') :
      check.status === 'skipped' ? c.yellow('  skip    ') :
      check.status === 'error'   ? c.red('  error   ') :
                                    c.dim('  ?       ');
    console.log(`${icon} ${name.padEnd(28)} ${c.dim(check.message)}`);
    if (check.status === 'fail' && check.details) {
      const detail = typeof check.details === 'string'
        ? check.details
        : JSON.stringify(check.details, null, 2);
      console.log(c.red(detail.split('\n').map((l) => '            ' + l).join('\n')));
    }
  }
  console.log('');
  console.log(`  ${banner}`);
  console.log('');
}

// ---------- scan mode ----------
const SCANNABLE_EXTS = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx',
  '.py', '.pyi',
  '.go', '.rs', '.rb', '.java', '.kt', '.swift',
  '.lua', '.php', '.cs', '.scala',
]);
const SCAN_EXCLUDE_DIRS = new Set([
  'node_modules', '.git', '.venv', 'venv', '__pycache__', 'dist', 'build',
  '.next', '.cache', '.pytest_cache', '.mypy_cache', '.tox', 'coverage',
  // Skip the canon's own fixtures by default — `vulnc scan` of a real
  // codebase shouldn't be polluted by the library's pedagogical examples.
  // The smoke test passes the fixture paths explicitly to enable matching.
  'vulnerable_fixture', 'patched_fixture',
]);

function loadAcceptedEntries(canonRoot) {
  const entriesDir = path.join(canonRoot, 'entries');
  if (!fs.existsSync(entriesDir)) return [];
  const out = [];
  for (const dir of fs.readdirSync(entriesDir)) {
    const ep = path.join(entriesDir, dir, 'entry.json');
    if (!fs.existsSync(ep)) continue;
    try {
      const entry = JSON.parse(fs.readFileSync(ep, 'utf8'));
      if (entry.status === 'accepted' && entry.detection && entry.detection.signature_regex) {
        out.push({ entry, dir: path.dirname(ep) });
      }
    } catch { /* skip */ }
  }
  return out;
}

// Test/exercise files are not code-under-scan; they are harnesses that
// exercise the patterns we're trying to catch. Scanning them would
// produce noisy false positives (a regression test exercises the bug
// shape on purpose). Keep the default conservative.
const TEST_FILE_PATTERNS = [
  /\.test\.[jt]sx?$/i,
  /\.spec\.[jt]sx?$/i,
  /(^|\/)test_[^/]+\.py$/i,
  /(^|\/)[^/]+_test\.py$/i,
  /(^|\/)__tests__\//i,
  /(^|\/)tests?\//i,
];

function isTestFile(p) {
  return TEST_FILE_PATTERNS.some((re) => re.test(p));
}

function* walk(targetDir) {
  const stack = [targetDir];
  while (stack.length) {
    const cur = stack.pop();
    let stat;
    try { stat = fs.statSync(cur); } catch { continue; }
    if (stat.isDirectory()) {
      const base = path.basename(cur);
      if (SCAN_EXCLUDE_DIRS.has(base)) continue;
      let names;
      try { names = fs.readdirSync(cur); } catch { continue; }
      for (const n of names) stack.push(path.join(cur, n));
      continue;
    }
    if (!stat.isFile()) continue;
    if (stat.size > 1_000_000) continue; // skip large files
    const ext = path.extname(cur).toLowerCase();
    if (!SCANNABLE_EXTS.has(ext)) continue;
    if (isTestFile(cur)) continue;
    yield cur;
  }
}

function scanFileAgainstEntries(filePath, entries) {
  let text;
  try { text = fs.readFileSync(filePath, 'utf8'); }
  catch { return []; }

  const findings = [];
  for (const { entry } of entries) {
    const sig = new RegExp(entry.detection.signature_regex, 'g');
    const exc = entry.detection.exclude_regex
      ? new RegExp(entry.detection.exclude_regex)
      : null;
    if (exc && exc.test(text)) continue; // patched-code signature present, suppress

    let m;
    while ((m = sig.exec(text)) !== null) {
      const before = text.slice(0, m.index);
      const line = before.split('\n').length;
      const lineStart = before.lastIndexOf('\n') + 1;
      const lineEnd = text.indexOf('\n', m.index);
      const snippet = text.slice(lineStart, lineEnd === -1 ? text.length : lineEnd).trim();
      findings.push({
        canon_id: entry.id,
        canon_title: entry.title,
        severity: entry.severity,
        confidence: (entry.detection && entry.detection.confidence) || 'medium',
        file: filePath,
        line,
        match: m[0],
        snippet: snippet.length > 200 ? snippet.slice(0, 200) + '…' : snippet,
        mitigation_summary: entry.mitigation && entry.mitigation.summary,
      });
      // Avoid pathological infinite loops on zero-length matches
      if (m.index === sig.lastIndex) sig.lastIndex++;
    }
  }
  return findings;
}

function cmdScan(targetDir, opts) {
  const absTarget = path.resolve(targetDir);
  if (!fs.existsSync(absTarget)) {
    console.error(c.red(`error: target not found: ${absTarget}`));
    process.exit(2);
  }
  const canonRoot = opts.canonRoot
    ? path.resolve(opts.canonRoot)
    : findCanonRoot(__dirname);
  let entries = loadAcceptedEntries(canonRoot);
  if (opts.only) {
    const wanted = new Set(opts.only.split(',').map((s) => s.trim()));
    entries = entries.filter(({ entry }) => wanted.has(entry.id));
    if (entries.length === 0) {
      console.error(c.red(`error: --only filter matched no entries (wanted: ${[...wanted].join(', ')})`));
      process.exit(2);
    }
  }
  if (entries.length === 0) {
    console.error(c.red(`error: no accepted entries with detection.signature_regex in ${canonRoot}`));
    process.exit(2);
  }

  const startedAt = new Date().toISOString();
  const allFindings = [];
  let filesScanned = 0;

  // If user wants to scan a fixture dir explicitly, allow it by clearing
  // the exclusion. Detect by checking if the target itself is under one.
  const exclude = new Set(SCAN_EXCLUDE_DIRS);
  if (/vulnerable_fixture|patched_fixture/.test(absTarget)) {
    exclude.delete('vulnerable_fixture');
    exclude.delete('patched_fixture');
  }
  // Patch the walk function's exclusion via env-style hack
  for (const dir of [...exclude]) SCAN_EXCLUDE_DIRS.add(dir);
  if (/vulnerable_fixture|patched_fixture/.test(absTarget)) {
    SCAN_EXCLUDE_DIRS.delete('vulnerable_fixture');
    SCAN_EXCLUDE_DIRS.delete('patched_fixture');
  }

  for (const file of walk(absTarget)) {
    filesScanned++;
    const findings = scanFileAgainstEntries(file, entries);
    allFindings.push(...findings);
  }

  const finishedAt = new Date().toISOString();
  const summary = {
    vulnc_version: VULNC_VERSION,
    target: absTarget,
    canon_root: canonRoot,
    entries_used: entries.map(({ entry }) => entry.id),
    files_scanned: filesScanned,
    finding_count: allFindings.length,
    started_at: startedAt,
    finished_at: finishedAt,
    findings: allFindings,
  };

  if (opts.json) {
    console.log(JSON.stringify(summary, null, 2));
    process.exit(allFindings.length === 0 ? 0 : 1);
  }

  console.log('');
  console.log(c.cyan(c.bold(`vulnc scan  ·  target: ${absTarget}`)));
  console.log(c.dim(`  ${entries.length} canon entries  ·  ${filesScanned} files scanned`));
  console.log('');
  if (allFindings.length === 0) {
    console.log(c.green(c.bold('  no findings')));
    console.log('');
    process.exit(0);
  }
  // Group by confidence tier (HIGH → MEDIUM → LOW), then by canon_id within tier
  const TIER_ORDER = ['high', 'medium', 'low'];
  const TIER_LABEL = {
    high:   c.red(c.bold('HIGH')),
    medium: c.yellow(c.bold('MEDIUM')),
    low:    c.dim('LOW'),
  };
  const TIER_HINT = {
    high:   'literal vulnerability shape — triage first',
    medium: 'pattern-true; exploitability depends on context',
    low:    'framework-level signal; human review required',
  };

  const byTier = { high: {}, medium: {}, low: {} };
  for (const f of allFindings) {
    const tier = byTier[f.confidence] ? f.confidence : 'medium';
    (byTier[tier][f.canon_id] ||= []).push(f);
  }
  const tierCounts = {};
  for (const tier of TIER_ORDER) {
    tierCounts[tier] = Object.values(byTier[tier]).reduce((s, a) => s + a.length, 0);
  }

  for (const tier of TIER_ORDER) {
    const tierFindings = byTier[tier];
    if (Object.keys(tierFindings).length === 0) continue;
    console.log(`  ${TIER_LABEL[tier]}  ${c.dim('— ' + TIER_HINT[tier] + '  (' + tierCounts[tier] + ')')}`);
    console.log('');
    for (const [canonId, fs_] of Object.entries(tierFindings)) {
      console.log(c.bold(c.yellow(`    ${canonId}  ·  ${fs_[0].canon_title}`)) +
                  c.dim(`  (${fs_.length} match${fs_.length === 1 ? '' : 'es'})`));
      for (const f of fs_) {
        const rel = path.relative(absTarget, f.file);
        console.log(`      ${c.cyan(rel)}:${c.bold(f.line)}  ${c.dim(f.snippet)}`);
      }
      console.log(c.dim(`      mitigation: ${fs_[0].mitigation_summary || '(see canon entry)'}`));
      console.log('');
    }
  }
  console.log(c.bold(`  ${allFindings.length} finding${allFindings.length === 1 ? '' : 's'}  ·  ` +
    `HIGH=${tierCounts.high}  MEDIUM=${tierCounts.medium}  LOW=${tierCounts.low}`));
  console.log('');

  // Write a scan report
  const reportsDir = path.join(canonRoot, 'reports', 'scans');
  fs.mkdirSync(reportsDir, { recursive: true });
  const tag = path.basename(absTarget).replace(/[^A-Za-z0-9_-]/g, '_');
  const reportPath = path.join(reportsDir, `scan-${tag}-${Date.now()}.json`);
  fs.writeFileSync(reportPath, JSON.stringify(summary, null, 2) + '\n');
  console.log(c.dim(`  report → ${path.relative(process.cwd(), reportPath)}`));
  console.log('');
  process.exit(allFindings.length === 0 ? 0 : 1);
}

// ---------- CLI ----------
function usage() {
  console.log(`vulnc v${VULNC_VERSION} — VulnCanon security compiler

Usage:
  vulnc check <entry-dir>
  vulnc check-all [canon-root]
  vulnc scan <target-dir> [--canon <canon-root>] [--json]
  vulnc --help | -h | --version

Exit codes:
  check / check-all
    0  every checked entry was ACCEPTED
    1  at least one entry was REJECTED
  scan
    0  no findings
    1  one or more findings (suspected vulnerabilities) reported
  any
    2  invocation error
`);
}

function cmdCheck(entryDir) {
  const absEntryDir = path.resolve(entryDir);
  if (!fs.existsSync(absEntryDir)) {
    console.error(c.red(`error: entry directory not found: ${absEntryDir}`));
    process.exit(2);
  }
  const canonRoot = findCanonRoot(absEntryDir);
  const schema = loadSchema();
  const report = checkEntry(absEntryDir, canonRoot, schema);
  printReport(report);
  const out = writeReport(report);
  console.log(c.dim(`  report → ${path.relative(process.cwd(), out)}`));
  console.log('');
  process.exit(report.overall_status === 'accepted' ? 0 : 1);
}

function cmdCheckAll(canonRootArg) {
  const canonRoot = path.resolve(canonRootArg || path.resolve(__dirname, '../../..'));
  const entriesDir = path.join(canonRoot, 'entries');
  if (!fs.existsSync(entriesDir)) {
    console.error(c.red(`error: no entries directory at ${entriesDir}`));
    process.exit(2);
  }
  const schema = loadSchema();
  const dirs = fs.readdirSync(entriesDir)
    .map((d) => path.join(entriesDir, d))
    .filter((p) => fs.statSync(p).isDirectory());

  console.log(c.cyan(c.bold(`vulnc check-all  ·  ${dirs.length} entries  ·  ${entriesDir}`)));

  const reports = dirs.map((d) => {
    const r = checkEntry(d, canonRoot, schema);
    writeReport(r);
    return r;
  });

  const accepted = reports.filter((r) => r.overall_status === 'accepted');
  const rejected = reports.filter((r) => r.overall_status !== 'accepted');

  console.log('');
  for (const r of reports) {
    const tag = r.overall_status === 'accepted'
      ? c.green('ACCEPTED')
      : c.red('REJECTED');
    const failed = Object.entries(r.checks)
      .filter(([, ch]) => ch.status === 'fail' || ch.status === 'error')
      .map(([n]) => n)
      .join(', ');
    console.log(`  ${tag}  ${r.entry_id.padEnd(20)} ${failed ? c.dim('failed: ' + failed) : ''}`);
  }
  console.log('');
  console.log(c.bold(`  ${accepted.length}/${reports.length} accepted`));
  console.log('');
  process.exit(rejected.length === 0 ? 0 : 1);
}

function main() {
  const [, , cmd, ...rest] = process.argv;
  if (!cmd || cmd === '--help' || cmd === '-h') { usage(); process.exit(0); }
  if (cmd === '--version' || cmd === '-v') { console.log(VULNC_VERSION); process.exit(0); }
  if (cmd === 'check') {
    if (!rest[0]) { console.error('error: vulnc check requires <entry-dir>'); process.exit(2); }
    return cmdCheck(rest[0]);
  }
  if (cmd === 'check-all') {
    return cmdCheckAll(rest[0]);
  }
  if (cmd === 'scan') {
    if (!rest[0]) { console.error('error: vulnc scan requires <target-dir>'); process.exit(2); }
    const target = rest[0];
    const opts = { canonRoot: null, json: false, only: null };
    for (let i = 1; i < rest.length; i++) {
      if (rest[i] === '--canon') { opts.canonRoot = rest[++i]; continue; }
      if (rest[i] === '--json')  { opts.json = true; continue; }
      if (rest[i] === '--only')  { opts.only = rest[++i]; continue; }
      console.error(`error: unknown scan option "${rest[i]}"`); process.exit(2);
    }
    return cmdScan(target, opts);
  }
  console.error(`error: unknown command "${cmd}"`); usage(); process.exit(2);
}

main();
