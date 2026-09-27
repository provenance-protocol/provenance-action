/**
 * check-code modes, end to end against real local git repositories and a
 * stand-in for the GitHub API. Runs the built action as GitHub does.
 */
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import http from 'node:http';
import YAML from 'yaml';
import { generateProvenanceKeyPair, signDeclaration } from 'provenance-protocol/keygen';

const run = promisify(execFile);
const ACTION = resolve('dist/index.js');
let pass = 0, fail = 0;
const t = (name, ok, extra = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`); ok ? pass++ : fail++; };
const g = (cwd, ...a) => execFileSync('git', a, { cwd, encoding: 'utf8' }).trim();

// Stand-in for the GitHub API: records pull-request calls.
const calls = [];
const server = http.createServer((req, res) => {
  let body = ''; req.on('data', (c) => (body += c)); req.on('end', () => {
    calls.push({ method: req.method, url: req.url, body: body ? JSON.parse(body) : null });
    res.setHeader('Content-Type', 'application/json');
    if (req.method === 'GET') return res.end('[]');
    res.statusCode = 201; res.end(JSON.stringify({ number: 7 }));
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const API = `http://127.0.0.1:${server.address().port}`;

const { publicKey, privateKey } = generateProvenanceKeyPair();

function repo(provenanceId) {
  const root = mkdtempSync(join(tmpdir(), 'modes-'));
  const origin = join(root, 'origin.git');
  const work = join(root, 'work');
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', origin]);
  execFileSync('git', ['clone', '-q', origin, work]);
  g(work, 'config', 'user.email', 't@t'); g(work, 'config', 'user.name', 't');
  const decl = { provenance: '0.2', name: 'A', description: 'B', version: '1.0.0', provenance_id: provenanceId, constraints: ['no:pii'], identity: { public_key: publicKey, algorithm: 'ed25519' } };
  decl.identity.signature = signDeclaration(privateKey, decl);
  writeFileSync(join(work, 'PROVENANCE.yml'), '# keep this comment\n' + YAML.stringify(decl));
  writeFileSync(join(work, 'package.json'), JSON.stringify({ name: 'a', version: '1.0.0' }));
  g(work, 'add', '-A'); g(work, 'commit', '-qm', 'init'); g(work, 'push', '-q', 'origin', 'HEAD:main');
  // The code moves on.
  writeFileSync(join(work, 'package.json'), JSON.stringify({ name: 'a', version: '1.1.0' }));
  g(work, 'commit', '-qam', 'bump'); g(work, 'push', '-q', 'origin', 'HEAD:main');
  const event = join(root, 'event.json');
  writeFileSync(event, JSON.stringify({ repository: { default_branch: 'main' } }));
  return { root, origin, work, event };
}

async function action(r, env) {
  const out = join(r.root, 'out.txt'); writeFileSync(out, '');
  try {
    const { stdout } = await run('node', [ACTION], { cwd: r.work, env: { ...process.env,
      'INPUT_FILE-PATH': 'PROVENANCE.yml', 'INPUT_CHECK-REPOSITORY': 'false', 'INPUT_GITHUB-TOKEN': 'test',
      GITHUB_OUTPUT: out, GITHUB_WORKSPACE: r.work, GITHUB_REPOSITORY: 'alice/agent', GITHUB_API_URL: API,
      GITHUB_EVENT_NAME: 'push', GITHUB_REF: 'refs/heads/main', GITHUB_EVENT_PATH: r.event, ...env } });
    return { failed: false, stdout };
  } catch (e) { return { failed: true, stdout: (e.stdout || '') + (e.stderr || '') }; }
}
const originFile = (r, ref) => execFileSync('git', ['--git-dir', r.origin, 'show', `${ref}:PROVENANCE.yml`], { encoding: 'utf8' });

// warn (default): reports, touches nothing.
let r = repo('provenance:domain:agent.example.com');
let res = await action(r, {});
t('warn: reports the outdated passport', !res.failed && /Passport out of date — version/.test(res.stdout), res.stdout.slice(-300));
t('warn: origin untouched', YAML.parse(originFile(r, 'main')).version === '1.0.0');

// automatic, service signs: commits facts to main, unsigned, comments kept.
r = repo('provenance:domain:agent.example.com');
res = await action(r, { 'INPUT_CHECK-CODE': 'automatic' });
let main = originFile(r, 'main');
t('automatic (service): the fact is committed to main', !res.failed && YAML.parse(main).version === '1.1.0', res.stdout.slice(-400));
t('automatic (service): left unsigned for the service to sign, comments kept', !YAML.parse(main).identity.signature && main.includes('# keep this comment'));
t('automatic (service): the promise is untouched', YAML.parse(main).constraints.includes('no:pii'));
t('automatic: no key was needed or used', !/private/i.test(res.stdout));

// automatic, developer signs: falls back to a pull request, main untouched, working copy restored.
r = repo('provenance:github:alice/agent');
calls.length = 0;
res = await action(r, { 'INPUT_CHECK-CODE': 'automatic' });
t('automatic (developer): falls back to suggest and says why', /opening a pull request instead/.test(res.stdout), res.stdout.slice(-400));
t('automatic (developer): main untouched', YAML.parse(originFile(r, 'main')).version === '1.0.0');
t('the proposal is on its own branch', YAML.parse(originFile(r, 'provenance/passport-update')).version === '1.1.0');
t('a pull request is opened against main, asking for a signature', calls.some((c) => c.method === 'POST' && c.body?.base === 'main' && /Sign before merging/.test(c.body.body)), JSON.stringify(calls));
t('the working copy is restored, so a later deploy ships nothing unmerged', YAML.parse(readFileSync(join(r.work, 'PROVENANCE.yml'), 'utf8')).version === '1.0.0' && g(r.work, 'rev-parse', '--abbrev-ref', 'HEAD') === 'main');

// suggest on a service-signed passport: pull request says merge publishes.
r = repo('provenance:domain:agent.example.com');
calls.length = 0;
res = await action(r, { 'INPUT_CHECK-CODE': 'suggest' });
t('suggest (service): pull request opened, merge to publish', calls.some((c) => c.method === 'POST' && /Merge to publish/.test(c.body?.body || '')));

// suggest acts only on pushes to the default branch.
r = repo('provenance:domain:agent.example.com');
calls.length = 0;
res = await action(r, { 'INPUT_CHECK-CODE': 'suggest', GITHUB_EVENT_NAME: 'pull_request', GITHUB_REF: 'refs/pull/3/merge' });
t('suggest on a pull request event: reports only, no branch, no API call', !res.failed && calls.length === 0 && /acts only on pushes to the default branch/.test(res.stdout));

// A developer-signed passport must not be merged unsigned.
r = repo('provenance:github:alice/agent');
const unsigned = YAML.parse(readFileSync(join(r.work, 'PROVENANCE.yml'), 'utf8')); delete unsigned.identity.signature;
writeFileSync(join(r.work, 'PROVENANCE.yml'), YAML.stringify(unsigned));
res = await action(r, { 'INPUT_CHECK-CODE': 'suggest', GITHUB_EVENT_NAME: 'pull_request', GITHUB_REF: 'refs/pull/3/merge' });
t('an unsigned developer passport fails its pull request', res.failed && /Sign it before merging/.test(res.stdout), res.stdout.slice(-300));

// No write permission: says exactly what is missing, does not fail silently.
r = repo('provenance:domain:agent.example.com');
g(r.work, 'remote', 'set-url', 'origin', join(r.root, 'no-such-remote.git'));
res = await action(r, { 'INPUT_CHECK-CODE': 'automatic' });
t('when the push is refused: a clear warning naming the permission', !res.failed && /permissions: contents: write/.test(res.stdout), res.stdout.slice(-300));
t('and it still reports the outdated passport rather than going quiet', /Passport out of date — version/.test(res.stdout));

server.close();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
