const core = require('@actions/core');
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

// Spec versions this action understands. 0.2 and 0.3 sign the whole declaration
// (0.3 adds pinned dependencies); 0.1 signs only the identity, leaving
// capabilities and constraints unprotected.
const KNOWN_SPEC_VERSIONS = ['0.1', '0.2', '0.3'];

// Standard vocabulary, read from the standard itself so the two cannot drift.
// See SPEC.md, Capability Vocabulary, in provenance-protocol.
const VOCABULARY = require('provenance-protocol/vocabulary.json');
const CANONICAL_CAPABILITIES = [
  ...Object.keys(VOCABULARY.capabilities),
  ...Object.values(VOCABULARY.namespaces ?? {}).flatMap((ns) => Object.keys(ns)),
];
const CANONICAL_CONSTRAINTS = [
  ...Object.keys(VOCABULARY.capabilities).map((c) => `no:${c}`),
  ...Object.keys(VOCABULARY.constraints?.additional ?? {}),
];

function validateProvenanceYml(content) {
  const errors = [];
  const warnings = [];

  // Parse YAML
  let parsed;
  try {
    parsed = yaml.load(content);
  } catch (e) {
    errors.push(`YAML parsing failed: ${e.message}`);
    return { valid: false, errors, warnings };
  }

  // Required fields
  if (!parsed.provenance) {
    errors.push('Missing required field: provenance');
  } else if (!KNOWN_SPEC_VERSIONS.includes(String(parsed.provenance))) {
    // Unknown versions warn rather than fail: a reader written for today's spec
    // must not break a build because a file uses a later one.
    warnings.push(
      `Provenance version "${parsed.provenance}" is not known to this action. Known versions: ${KNOWN_SPEC_VERSIONS.join(', ')}`
    );
  }

  if (!parsed.name) {
    errors.push('Missing required field: name');
  } else if (typeof parsed.name !== 'string' || parsed.name.trim().length === 0) {
    errors.push('Field "name" must be a non-empty string');
  }

  if (!parsed.description) {
    errors.push('Missing required field: description');
  } else if (typeof parsed.description !== 'string' || parsed.description.trim().length === 0) {
    errors.push('Field "description" must be a non-empty string');
  }

  // Optional but recommended fields
  if (!parsed.version) {
    warnings.push('Recommended field missing: version');
  }

  if (!parsed.contact) {
    warnings.push('Recommended field missing: contact');
  } else {
    if (!parsed.contact.name && !parsed.contact.email && !parsed.contact.url) {
      warnings.push('Contact should include at least one of: name, email, url');
    }
  }

  // Capabilities validation
  if (parsed.capabilities) {
    if (!Array.isArray(parsed.capabilities)) {
      errors.push('Field "capabilities" must be an array');
    } else {
      parsed.capabilities.forEach(cap => {
        if (typeof cap !== 'string') {
          errors.push(`Capability must be a string: ${cap}`);
        } else if (!CANONICAL_CAPABILITIES.includes(cap)) {
          warnings.push(`Non-standard capability: "${cap}". Consider using: ${CANONICAL_CAPABILITIES.join(', ')}`);
        }
      });
    }
  }

  // Constraints validation
  if (parsed.constraints) {
    if (!Array.isArray(parsed.constraints)) {
      errors.push('Field "constraints" must be an array');
    } else {
      parsed.constraints.forEach(con => {
        if (typeof con !== 'string') {
          errors.push(`Constraint must be a string: ${con}`);
        } else if (!CANONICAL_CONSTRAINTS.includes(con)) {
          warnings.push(`Non-standard constraint: "${con}". Consider using: ${CANONICAL_CONSTRAINTS.join(', ')}`);
        }
      });
    }
  }

  // Model validation
  if (parsed.model) {
    if (typeof parsed.model !== 'object') {
      errors.push('Field "model" must be an object');
    } else {
      if (!parsed.model.provider) {
        errors.push('Field "model.provider" is required when model is specified');
      }
      if (!parsed.model.model_id) {
        warnings.push('Recommended field missing: model.model_id');
      }
    }
  }

  // provenance_id recommendation
  if (!parsed.provenance_id) {
    warnings.push('Recommended field missing: provenance_id (e.g. provenance:github:your-org/your-agent or provenance:domain:agent.example.com)');
  }

  // Identity block validation (for verified agents)
  if (parsed.identity) {
    if (typeof parsed.identity !== 'object') {
      errors.push('Field "identity" must be an object');
    } else {
      if (!parsed.identity.public_key) {
        errors.push('Field "identity.public_key" is required when identity is specified');
      }
      if (!parsed.identity.algorithm) {
        warnings.push('Recommended field missing: identity.algorithm (expected: ed25519)');
      } else if (parsed.identity.algorithm !== 'ed25519') {
        warnings.push(`identity.algorithm "${parsed.identity.algorithm}" is non-standard. Expected: ed25519`);
      }
      if (!parsed.identity.signature) {
        warnings.push(
          'identity.signature is missing — this declaration is not tamper-evident. Sign it with signDeclaration() from provenance-protocol/keygen'
        );
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    parsed
  };
}

/**
 * Verify the declaration's signature, and check that it belongs to this repo.
 *
 * Shape validation cannot catch the two failures that actually matter: a
 * declaration edited after it was signed, and a fork carrying the original's
 * declaration. Both look perfectly well-formed.
 */
async function verifyIdentity(parsed, { checkRepository }) {
  const errors = [];
  const warnings = [];
  const notes = [];
  let signatureState = 'none';

  // The verifier is ESM; this action is CommonJS. A dynamic import is bundled
  // as an async chunk, so dist/ still runs standalone with no node_modules.
  const { verifyDeclaration, checkLocation } = await import('provenance-protocol/verify');

  if (parsed.identity && parsed.identity.signature) {
    const result = await verifyDeclaration(parsed);

    if (!result.valid) {
      signatureState = 'invalid';
      errors.push(
        `identity.signature does not verify: ${result.reason || 'unknown reason'}. ` +
          'If you edited this file after signing it, re-sign it.'
      );
    } else if ((signatureState = result.coverage) === 'identity') {
      // Valid, but for 0.1 that means far less than people assume.
      warnings.push(
        'identity.signature is valid but covers only provenance_id and public_key — your declared ' +
          'capabilities and constraints are NOT protected by it. Set provenance: "0.2" and re-sign ' +
          'with signDeclaration() to cover the whole declaration.'
      );
    } else {
      notes.push('identity.signature verifies and covers the whole declaration');
    }
  }

  // In CI we know which repository we are in, so the location check that a
  // remote verifier would do can be done here — and it catches a fork that kept
  // the upstream declaration, which is the impersonation case.
  const repo = process.env.GITHUB_REPOSITORY;
  if (checkRepository && repo && typeof parsed.provenance_id === 'string') {
    const location = checkLocation(parsed.provenance_id, `https://github.com/${repo}`);
    if (location === 'mismatch') {
      errors.push(
        `provenance_id "${parsed.provenance_id}" does not name this repository (${repo}). ` +
          'If this is a fork, change provenance_id to your own repository or remove the declaration — ' +
          "as it stands the file claims to be someone else's agent."
      );
    } else if (location === 'match') {
      notes.push(`provenance_id matches this repository (${repo})`);
    }
  }

  return { errors, warnings, notes, signatureState };
}

/**
 * Issue a signed release notice: "this release shipped with this declaration".
 * Opt-in — it needs the agent's private key as a CI secret, which not every
 * operator will want to hold there. Every reason it does not happen is said
 * out loud; a release notice that silently fails to appear looks exactly like
 * one that was never configured.
 */
async function releaseNotice(parsed, privateKey) {
  const { keyFingerprint, declarationDigest } = await import('provenance-protocol/verify');
  const { signNotice } = await import('provenance-protocol/keygen');
  const { createPrivateKey, createPublicKey } = require('crypto');

  const version = core.getInput('release-version') ||
    (process.env.GITHUB_REF_TYPE === 'tag' ? process.env.GITHUB_REF_NAME : '');
  if (!version) {
    return { skipped: 'no release version — set release-version, or run on a tag' };
  }
  const provenanceId = parsed.provenance_id;
  const publicKey = parsed.identity && parsed.identity.public_key;
  if (typeof provenanceId !== 'string' || typeof publicKey !== 'string') {
    return { error: 'a release notice needs provenance_id and identity.public_key in the declaration' };
  }

  let derived;
  try {
    const priv = createPrivateKey({ key: Buffer.from(privateKey, 'base64'), format: 'der', type: 'pkcs8' });
    derived = Buffer.from(createPublicKey(priv).export({ type: 'spki', format: 'der' })).toString('base64');
  } catch {
    return { error: 'release-private-key is not a base64 PKCS8 Ed25519 key' };
  }
  if (derived !== publicKey) {
    return { error: 'release-private-key does not match identity.public_key in the declaration' };
  }

  let digest;
  try {
    digest = await declarationDigest(parsed);
  } catch (e) {
    return { error: `declaration cannot be digested: ${e.message}` };
  }

  const sha = process.env.GITHUB_SHA;
  const repo = process.env.GITHUB_REPOSITORY;
  const notice = {
    notice: '0.1',
    id: `release-${version}-${(sha || '').slice(0, 12) || Date.now().toString(36)}`,
    event: 'release',
    provenance_id: provenanceId,
    key_fingerprint: await keyFingerprint(publicKey),
    issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    claims: {
      version,
      ...(sha && /^[0-9a-f]{7,64}$/.test(sha) ? { commit: sha } : {}),
      declaration_digest: digest,
      ...(repo ? { repository: `${process.env.GITHUB_SERVER_URL || 'https://github.com'}/${repo}` } : {}),
    },
  };
  return { notice: { ...notice, signature: signNotice(privateKey, notice) } };
}

async function deliver(notice, urls) {
  for (const url of urls) {
    try {
      if (new URL(url).protocol !== 'https:') throw new Error('watcher URLs must be https');
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(notice),
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      core.info(`\u2713 Release notice delivered to ${url}`);
    } catch (e) {
      // A watcher being down must not fail the release, but must not pass
      // unnoticed either.
      core.warning(`Release notice not delivered to ${url}: ${e.message}`);
    }
  }
}

/**
 * Compare the declaration with the project on every build, using the same
 * local check as `provenance check`. Suggestions are warnings; a clash with a
 * promise fails the build only in strict mode. Nothing is sent anywhere.
 */
const UPDATE_BRANCH = 'provenance/passport-update';

function git(args, cwd) {
  const { execFileSync } = require('child_process');
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function describeFinding(f) {
  const v = f.field === 'dependencies' ? (f.value.provenance_id || f.value.url) : f.value;
  return `${f.field}: ${f.change === 'modified' ? `${f.from} -> ` : '+ '}${v} (${f.reason})`;
}

// Who signs the passport once its contents change. A service running
// provenance-middleware signs at start-up with the key it already holds; a file
// published in the repository must be signed by the developer. Neither needs
// the key in CI — which is the point.
function signedBy(parsed) {
  const input = core.getInput('signed-by') || 'auto';
  if (input === 'service' || input === 'developer') return input;
  return String(parsed.provenance_id || '').startsWith('provenance:domain:') ? 'service' : 'developer';
}

function onDefaultBranchPush() {
  if (process.env.GITHUB_EVENT_NAME !== 'push') return false;
  let branch = null;
  try { branch = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')).repository.default_branch; } catch { /* unknown */ }
  return Boolean(branch) && process.env.GITHUB_REF === `refs/heads/${branch}` ? branch : false;
}

async function githubApi(method, route, body) {
  const token = core.getInput('github-token');
  if (!token) throw new Error('no github-token');
  const base = process.env.GITHUB_API_URL || 'https://api.github.com';
  const res = await fetch(`${base}${route}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`GitHub API ${res.status}: ${data.message || 'error'}`);
  return data;
}

/**
 * Compare the declaration with the project on every build, using the same
 * local check as `provenance check`. Nothing is sent anywhere, and no key is
 * used: updates are written unsigned and signed where the key already lives.
 *
 *   warn       warnings, and the command that fixes them (default)
 *   suggest    on pushes to the default branch, open a pull request with the facts applied
 *   automatic  on pushes to the default branch, commit the facts directly — only when
 *              the running service signs (signed-by: service); otherwise as suggest
 *   strict     fail the build while anything is outstanding
 */
async function checkCode(parsed, filePath, mode) {
  const { checkProject, updateDeclarationText } = await import('provenance-protocol/check');
  const abs = path.resolve(filePath);
  const r = checkProject(path.dirname(abs), parsed);
  const conflicts = r.conflicts.map((c) => `Code conflicts with the promise ${c.promise} (${c.reason}). Change the code, or remove the promise yourself and re-sign.`);
  const out = { conflicts, outstanding: r.certain.length + r.likely.length, errors: [] };
  if (r.inSync) { core.info('✓ Passport matches the project'); return out; }

  const warnAll = () => {
    for (const f of r.certain) core.warning(`Passport out of date — ${describeFinding(f)}. Run: npx provenance-protocol check --update`);
    for (const f of r.likely) core.warning(`Please confirm — ${describeFinding(f)}. Run: npx provenance-protocol check --update, or list "${f.key}" in .provenance-ignore`);
  };
  if (mode === 'warn' || mode === 'strict') { warnAll(); return out; }

  const base = onDefaultBranchPush();
  if (!base) {
    core.info(`check-code: ${mode} acts only on pushes to the default branch; reporting instead.`);
    warnAll(); return out;
  }
  for (const f of r.likely) core.warning(`Please confirm — ${describeFinding(f)}. Not applied automatically: run npx provenance-protocol check --update.`);
  if (!r.certain.length) return out;

  const who = signedBy(parsed);
  let effective = mode;
  if (mode === 'automatic' && who === 'developer') {
    effective = 'suggest';
    core.warning('check-code: automatic needs the running service to sign (signed-by: service). This passport is published as a file, so a person must sign it — opening a pull request instead.');
  }

  const cwd = process.env.GITHUB_WORKSPACE || process.cwd();
  const rel = path.relative(cwd, abs);
  const { text } = updateDeclarationText(fs.readFileSync(abs, 'utf8'), r.certain, { json: /\.json$/i.test(abs) });
  const summary = r.certain.map((f) => `- ${describeFinding(f)}`).join('\n');
  const msg = `Update ${rel} from provenance check\n\n${summary}\n\nFacts only; no promise changed. Unsigned: ${who === 'service' ? 'the running service signs it at start-up.' : 'sign it before merging (npx provenance-protocol sign).'}`;

  // The working copy must end exactly where it started: later steps in the
  // same job (a deploy) must never ship an unmerged proposal.
  let origRef = null;
  let origSha = null;
  const restore = () => {
    if (effective !== 'suggest' || !origSha) return;
    try {
      if (origRef && origRef !== 'HEAD') git(['checkout', '-f', origRef], cwd);
      else git(['checkout', '-f', '--detach', origSha], cwd);
    } catch (e) {
      core.warning(`Could not restore the working copy after preparing the update: ${e.message}`);
    }
  };
  try {
    origRef = git(['rev-parse', '--abbrev-ref', 'HEAD'], cwd);
    origSha = git(['rev-parse', 'HEAD'], cwd);
    git(['config', 'user.name', 'github-actions[bot]'], cwd);
    git(['config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com'], cwd);
    if (effective === 'automatic') {
      fs.writeFileSync(abs, text);
      git(['add', rel], cwd);
      git(['commit', '-m', msg], cwd);
      git(['push', 'origin', `HEAD:refs/heads/${base}`], cwd);
      core.info(`✓ Passport updated on ${base}; your service signs it on its next start.`);
      return out;
    }
    git(['checkout', '-B', UPDATE_BRANCH], cwd);
    fs.writeFileSync(abs, text);
    git(['add', rel], cwd);
    git(['commit', '-m', msg], cwd);
    git(['push', '-f', 'origin', UPDATE_BRANCH], cwd);
    restore();
  } catch (e) {
    restore();
    core.warning(`Could not ${effective === 'automatic' ? 'commit' : 'push'} the passport update (${(e.stderr || e.message || '').toString().split('\n')[0]}). Give the workflow "permissions: contents: write"${effective === 'suggest' ? ' and "pull-requests: write"' : ''}. Reporting instead.`);
    warnAll(); return out;
  }

  const [owner] = (process.env.GITHUB_REPOSITORY || '/').split('/');
  const body = [
    'The passport no longer matches the code. This applies the facts `provenance check` found:',
    '', summary, '',
    r.likely.length ? `To confirm yourself (not applied): \n${r.likely.map((f) => `- ${describeFinding(f)}`).join('\n')}\nRun \`npx provenance-protocol check --update\`.\n` : '',
    conflicts.length ? `**Conflicts with a promise** (never changed for you):\n${conflicts.map((c) => `- ${c}`).join('\n')}\n` : '',
    who === 'service'
      ? 'No promise was changed. The file is unsigned on purpose: your service signs it at start-up. Merge to publish.'
      : '**Sign before merging:** check out this branch and run `npx provenance-protocol sign`. Your key stays on your machine. This check fails on this pull request until it is signed.',
  ].filter(Boolean).join('\n');
  try {
    const open = await githubApi('GET', `/repos/${process.env.GITHUB_REPOSITORY}/pulls?state=open&head=${owner}:${UPDATE_BRANCH}`);
    if (open.length) {
      await githubApi('PATCH', `/repos/${process.env.GITHUB_REPOSITORY}/pulls/${open[0].number}`, { body });
      core.info(`✓ Passport update refreshed in pull request #${open[0].number}`);
    } else {
      const pr = await githubApi('POST', `/repos/${process.env.GITHUB_REPOSITORY}/pulls`, { title: 'Update the passport to match the code', head: UPDATE_BRANCH, base, body });
      core.info(`✓ Passport update proposed in pull request #${pr.number}`);
    }
  } catch (e) {
    core.warning(`Passport update pushed to branch ${UPDATE_BRANCH}, but the pull request could not be opened (${e.message}). Give the workflow "permissions: pull-requests: write".`);
  }
  return out;
}

async function run() {
  try {
    const filePath = core.getInput('file-path') || 'PROVENANCE.yml';
    // Default to true when the input is absent. action.yml declares 'true', and
    // an action that quietly stops failing because an input was not passed is
    // the worst kind of broken check: every build goes green regardless.
    const failOnError = (core.getInput('fail-on-error') || 'true') === 'true';
    const verifySignature = (core.getInput('verify-signature') || 'true') === 'true';
    const requireSignature = (core.getInput('require-signature') || 'false') === 'true';
    const checkRepository = (core.getInput('check-repository') || 'true') === 'true';

    // Check if file exists
    if (!fs.existsSync(filePath)) {
      core.setFailed(`PROVENANCE.yml not found at: ${filePath}`);
      core.setOutput('valid', 'false');
      core.setOutput('errors', 'File not found');
      return;
    }

    // Read and validate
    const content = fs.readFileSync(filePath, 'utf8');
    const result = validateProvenanceYml(content);

    if (requireSignature && result.parsed && !(result.parsed.identity && result.parsed.identity.signature)) {
      result.errors.push('identity.signature is required (require-signature is enabled) but is absent');
      result.valid = false;
    }

    // Only worth verifying a file that parsed; a shape failure already reported.
    if (verifySignature && result.parsed) {
      try {
        const identity = await verifyIdentity(result.parsed, { checkRepository });
        result.errors.push(...identity.errors);
        result.warnings.push(...identity.warnings);
        identity.notes.forEach((n) => core.info(`\u2713 ${n}`));
        if (identity.errors.length > 0) result.valid = false;
        core.setOutput('signature', identity.signatureState);
      } catch (e) {
        // A verifier that cannot run must not be reported as a bad declaration.
        core.warning(`Signature could not be verified: ${e.message}. The declaration was not checked cryptographically.`);
        core.setOutput('signature', 'unchecked');
      }
    }

    const codeMode = core.getInput('check-code') || 'warn';
    if (!['off', 'warn', 'suggest', 'automatic', 'strict'].includes(codeMode)) {
      result.errors.push(`check-code must be off, warn, suggest, automatic or strict (got "${codeMode}")`);
      result.valid = false;
    } else if (codeMode !== 'off' && result.parsed) {
      try {
        const c = await checkCode(result.parsed, filePath, codeMode);
        if (codeMode === 'strict') {
          result.errors.push(...c.conflicts);
          if (c.outstanding) result.errors.push(`${c.outstanding} passport update(s) outstanding (strict mode)`);
          if (c.conflicts.length || c.outstanding) result.valid = false;
        } else {
          c.conflicts.forEach((m) => core.warning(m));
        }
      } catch (e) {
        // Could not check is not the same as checked and found nothing.
        core.warning(`Code check could not run: ${e.message}. The passport was not compared with the project.`);
      }

      // In the propose/apply flows a developer-signed passport must never be
      // merged unsigned: it would publish as "not genuine".
      if (['suggest', 'automatic'].includes(codeMode) && process.env.GITHUB_EVENT_NAME === 'pull_request'
          && signedBy(result.parsed) === 'developer' && result.parsed.identity && !result.parsed.identity.signature) {
        result.errors.push('The passport is unsigned. Sign it before merging: npx provenance-protocol sign (your key stays on your machine).');
        result.valid = false;
      }
    }

    const releaseKey = core.getInput('release-private-key');
    if (releaseKey) {
      core.setSecret(releaseKey);
      if (!result.valid || !result.parsed) {
        core.warning('Release notice not issued: the declaration did not pass validation.');
      } else {
        const r = await releaseNotice(result.parsed, releaseKey);
        if (r.skipped) {
          core.warning(`Release notice not issued: ${r.skipped}.`);
        } else if (r.error) {
          result.errors.push(`Release notice: ${r.error}`);
          result.valid = false;
        } else {
          core.setOutput('release-notice', JSON.stringify(r.notice));
          core.info(`\u2713 Signed release notice for ${r.notice.claims.version}`);
          const urls = (core.getInput('notify-urls') || '').split(/[\s,]+/).filter(Boolean);
          await deliver(r.notice, urls);
        }
      }
    }

    // Output results
    core.setOutput('valid', result.valid ? 'true' : 'false');
    core.setOutput('errors', result.errors.join('\n'));

    // Log warnings
    if (result.warnings.length > 0) {
      core.warning('PROVENANCE.yml validation warnings:');
      result.warnings.forEach(w => core.warning(`  - ${w}`));
    }

    // Log errors
    if (result.errors.length > 0) {
      core.error('PROVENANCE.yml validation failed:');
      result.errors.forEach(e => core.error(`  - ${e}`));
      
      if (failOnError) {
        core.setFailed('PROVENANCE.yml validation failed. See errors above.');
      }
    } else {
      core.info('✓ PROVENANCE.yml is valid');
      if (result.warnings.length === 0) {
        core.info('✓ No warnings');
      }
    }

  } catch (error) {
    core.setFailed(`Action failed: ${error.message}`);
  }
}

run();
