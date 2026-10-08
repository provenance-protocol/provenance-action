/**
 * Runs the built action the way GitHub runs it: as a subprocess with inputs in
 * the environment, reading a file from disk.
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateProvenanceKeyPair, signDeclaration, signForProvenance } from 'provenance-protocol/keygen';
import { stringify } from 'yaml';

let pass = 0, fail = 0;
const t = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`);
  ok ? pass++ : fail++;
};

const dir = mkdtempSync(join(tmpdir(), 'action-'));
const { publicKey, privateKey } = generateProvenanceKeyPair();
const REPO = 'alice/research-agent';
const ID = `provenance:github:${REPO}`;

function runAction(declaration, env = {}) {
  const file = join(dir, `${Math.random().toString(36).slice(2)}.yml`);
  writeFileSync(file, stringify(declaration));
  const outFile = join(dir, 'out.txt');
  writeFileSync(outFile, '');
  try {
    const stdout = execFileSync('node', ['dist/index.js'], {
      env: {
        ...process.env,
        'INPUT_FILE-PATH': file,
        GITHUB_OUTPUT: outFile,
        GITHUB_REPOSITORY: REPO,
        ...env,
      },
      encoding: 'utf8',
    });
    return { failed: false, stdout, outputs: readFileSync(outFile, 'utf8') };
  } catch (e) {
    return { failed: true, stdout: (e.stdout || '') + (e.stderr || ''), outputs: readFileSync(outFile, 'utf8') };
  }
}

const base = {
  provenance: '0.2', name: 'Research Agent', description: 'Searches and summarises.',
  provenance_id: ID, capabilities: ['read:web'], constraints: ['no:pii'],
  identity: { public_key: publicKey, algorithm: 'ed25519' },
};
const signed = { ...base, identity: { ...base.identity, signature: signDeclaration(privateKey, base) } };

// 1. a correctly signed 0.2 declaration in its own repo
let r = runAction(signed);
t('accepts a correctly signed 0.2 declaration', !r.failed, r.stdout.slice(-300));
t('reports the whole declaration is covered', r.outputs.includes('declaration'), r.outputs);
t('no spurious version warning', !r.stdout.includes('not known to this action'));

// 1b. a 0.3 declaration with a pinned dependency: known, verified, and still tamper-evident
const base3 = { ...base, provenance: '0.3', dependencies: [{ provenance_id: 'provenance:domain:model.example', pin: { version: '4.1' } }] };
const signed3 = { ...base3, identity: { ...base3.identity, signature: signDeclaration(privateKey, base3) } };
r = runAction(signed3);
t('accepts a correctly signed 0.3 declaration with a pinned dependency', !r.failed && r.outputs.includes('declaration'), r.stdout.slice(-300));
t('no version warning for 0.3', !r.stdout.includes('not known to this action'), r.stdout.slice(-300));
r = runAction({ ...signed3, dependencies: [{ provenance_id: 'provenance:domain:model.example', pin: { version: '9.9' } }] });
t('rejects a 0.3 declaration whose pin was changed after signing', r.failed && r.stdout.includes('does not verify'), r.stdout.slice(-200));

// 2. THE CASE SHAPE VALIDATION CANNOT CATCH: edited after signing
r = runAction({ ...signed, constraints: [] });
t('rejects a declaration edited after signing', r.failed);
t('and says why', r.stdout.includes('does not verify'), r.stdout.slice(-200));

// 3. a fork carrying the upstream declaration
r = runAction(signed, { GITHUB_REPOSITORY: 'mallory/research-agent-fork' });
t('rejects a fork carrying the original declaration', r.failed);
t('and explains the fix', r.stdout.includes('fork'), r.stdout.slice(-200));

// 4. a 0.1 declaration still passes, with an honest warning
const decl01 = { ...base, provenance: '0.1' };
const signed01 = { ...decl01, identity: { ...decl01.identity, signature: signForProvenance(privateKey, ID, publicKey) } };
r = runAction(signed01);
t('accepts a valid 0.1 declaration', !r.failed, r.stdout.slice(-300));
t('warns that 0.1 leaves constraints unprotected', r.stdout.includes('NOT protected'));
t('reports identity-only coverage', r.outputs.includes('identity'), r.outputs);

// 5. unsigned: allowed by default, rejected when required
r = runAction(base);
t('allows an unsigned declaration by default', !r.failed);
r = runAction(base, { 'INPUT_REQUIRE-SIGNATURE': 'true' });
t('rejects an unsigned declaration when required', r.failed);

// 6. opting out
r = runAction(signed, { GITHUB_REPOSITORY: 'mallory/fork', 'INPUT_CHECK-REPOSITORY': 'false' });
t('repository check can be disabled', !r.failed, r.stdout.slice(-200));

// 7. signed release notice — opt-in
const { verifyNotice, declarationDigest } = await import('provenance-protocol/verify');
function output(outputs, name) {
  const m = new RegExp(`${name}<<(\\S+)\\n([\\s\\S]*?)\\n\\1`).exec(outputs);
  return m ? m[2] : null;
}
r = runAction(signed, { 'INPUT_RELEASE-PRIVATE-KEY': privateKey, 'INPUT_RELEASE-VERSION': '4.2.0', GITHUB_SHA: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678' });
const noticeJson = output(r.outputs, 'release-notice');
t('issues a release notice when given the key', !r.failed && !!noticeJson, r.stdout.slice(-300));
if (noticeJson) {
  const notice = JSON.parse(noticeJson);
  const v = await verifyNotice(notice, { publicKey });
  t('the release notice verifies against the agent key', v.valid && v.event === 'release', v.reason);
  t('it ties the release to the declaration digest', notice.claims.declaration_digest === await declarationDigest(signed) && notice.claims.version === '4.2.0' && notice.claims.commit.startsWith('a1b2c3'));
  // The one permitted occurrence is the ::add-mask:: command, which GitHub
  // consumes to redact the value everywhere else and never displays.
  const leaks = r.stdout.split('\n').filter((l) => l.includes(privateKey) && !l.startsWith('::add-mask::'));
  t('the key is masked and never printed', r.stdout.includes(`::add-mask::${privateKey}`) && leaks.length === 0, leaks.join('|').slice(0, 80));
}
r = runAction(signed, { 'INPUT_RELEASE-PRIVATE-KEY': generateProvenanceKeyPair().privateKey, 'INPUT_RELEASE-VERSION': '4.2.0' });
t('refuses a release key that does not match the declaration', r.failed && r.stdout.includes('does not match'), r.stdout.slice(-300));
r = runAction(signed, { 'INPUT_RELEASE-PRIVATE-KEY': privateKey, GITHUB_REF_TYPE: 'branch' });
t('says so when there is no version to release', !r.failed && r.stdout.includes('Release notice not issued') && !output(r.outputs, 'release-notice'), r.stdout.slice(-300));
r = runAction(signed);
t('no key, no notice, no noise', !r.failed && !output(r.outputs, 'release-notice') && !r.stdout.includes('Release notice'));

// 8. code check: suggest warns, strict fails on a promise conflict
{
  const proj = mkdtempSync(join(tmpdir(), 'proj-'));
  writeFileSync(join(proj, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { nodemailer: '6' } }));
  const decl = { ...base, version: '1.0.0', constraints: ['no:pii', 'no:write:email'] };
  const signedDecl = { ...decl, identity: { ...decl.identity, signature: signDeclaration(privateKey, decl) } };
  const file = join(proj, 'PROVENANCE.yml');
  writeFileSync(file, stringify(signedDecl));
  const runIn = (env) => {
    const outFile = join(dir, 'out2.txt'); writeFileSync(outFile, '');
    try {
      return { failed: false, stdout: execFileSync('node', ['dist/index.js'], { env: { ...process.env, 'INPUT_FILE-PATH': file, GITHUB_OUTPUT: outFile, GITHUB_REPOSITORY: REPO, ...env }, encoding: 'utf8' }) };
    } catch (e) { return { failed: true, stdout: (e.stdout || '') + (e.stderr || '') }; }
  };
  let c = runIn({});
  t('warn (default): a promise conflict warns but does not fail', !c.failed && /conflicts with the promise no:write:email/.test(c.stdout), c.stdout.slice(-300));
  c = runIn({ 'INPUT_CHECK-CODE': 'strict' });
  t('strict: a promise conflict fails the build', c.failed && /no:write:email/.test(c.stdout), c.stdout.slice(-300));
  c = runIn({ 'INPUT_CHECK-CODE': 'off' });
  t('off: no code check', !c.failed && !/conflicts with the promise/.test(c.stdout));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
