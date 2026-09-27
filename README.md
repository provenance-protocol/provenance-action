# Provenance GitHub Action

Validates a `PROVENANCE.yml` **and cryptographically verifies it** — catching the
two failures that a shape check cannot see:

- a declaration **edited after it was signed** (the signature no longer matches)
- a **fork carrying the upstream declaration**, which claims to be someone else's agent

Both look perfectly well-formed to a validator.

Validates your `PROVENANCE.yml` file against the [Provenance Protocol](https://github.com/provenance-protocol/provenance-protocol/blob/main/SPEC.md) specification in CI/CD.

## Usage

Add this to your `.github/workflows/provenance.yml`:

```yaml
name: Validate Agent Identity
on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: provenance-protocol/provenance-action@v1
        with:
          file-path: 'PROVENANCE.yml'  # default
          fail-on-error: 'true'         # default
```

## What it checks

### Required Fields
- `provenance`: Spec version — `"0.2"` for new declarations, `"0.1"` legacy
- `name`: Agent name
- `description`: Agent description

### Recommended Fields
- `version`: Agent version
- `contact`: Contact information (name, email, or url)
- `capabilities`: What the agent can do
- `constraints`: What the agent will never do
- `model`: LLM provider and model ID

### Taxonomy Validation

The action warns about non-standard capabilities and constraints, encouraging use of canonical terms:

**Standard Capabilities:**
- `read:web`, `read:filesystem`, `write:filesystem`
- `execute:code`, `network:outbound`
- `database:read`, `database:write`, `api:external`

**Standard Constraints:**
- `no:financial:transact`, `no:pii`, `no:data:export`
- `no:code:execute`, `no:system:modify`

## Outputs

- `valid`: `"true"` or `"false"`
- `errors`: Validation errors (newline-separated)

## Keeping the passport true

On every build the action compares the declaration with the project — the same
local check as `npx provenance-protocol check`. The code is read inside your own
pipeline; nothing is sent anywhere, and **no key is ever needed in CI**.

| `check-code` | What happens when the passport is out of date |
|---|---|
| `warn` (default) | A warning, and the one command that fixes it |
| `suggest` (recommended) | On pushes to your default branch, a pull request with the facts applied |
| `automatic` | On pushes to your default branch, the facts are committed directly — when your running service signs the passport |
| `strict` | The build fails until it is up to date |
| `off` | No comparison |

Only facts the project states outright are ever applied (version, the AI
provider's library, servers in your MCP settings). Inferences are listed for
you to confirm, and a clash with a promise is reported and **never** changed
for you — dropping a promise is a public weakening a person must decide.

**Who signs the update** (`signed-by`, default `auto`):

- `service` — your service runs `provenance-middleware`, which signs the
  passport every time it starts. Updates are written unsigned and your service
  signs them on its next start. Both `suggest` and `automatic` work fully.
- `developer` — the passport is a file published in your repository. The pull
  request asks you to run `npx provenance-protocol sign` on its branch before
  merging, so the key stays on your machine; the action fails that pull request
  until it is signed. `automatic` falls back to a pull request, because nothing
  in CI can sign without your key.
- `auto` — `service` for `provenance:domain:` identifiers, `developer` otherwise.

`suggest` and `automatic` need the workflow to be allowed to write:

```yaml
permissions:
  contents: write
  pull-requests: write
```

Without it the action says exactly which permission is missing and falls back
to a warning. They never act on pull requests or other branches, and the
working copy is restored afterwards, so a later deploy step in the same job
never ships an unmerged proposal.

## Signed release notes (optional)

Give the action the agent's private key and it issues a signed notice tying
this release to the exact declaration it shipped with — which build carried
which promises. Send it to any watchers you choose, or none.

```yaml
      - uses: provenance-protocol/provenance-action@v1
        with:
          release-private-key: ${{ secrets.PROVENANCE_PRIVATE_KEY }}
          notify-urls: 'https://watcher.example/notices'   # optional
```

On a tag the version is the tag name; otherwise set `release-version`. The
notice is also available as the `release-notice` output. The key is masked in
logs and used only in the runner. Holding it as a CI secret is a trade-off; if
you would rather not, `provenance-middleware` announces each deployment from
the running service instead.

## Example PROVENANCE.yml

```yaml
provenance: "0.2"
name: "Research Assistant"
description: "Autonomous research agent that gathers and summarizes information"
version: "2.1.0"
provenance_id: "provenance:github:alice/research-assistant"

capabilities:
  - read:web
  - write:summaries

constraints:
  - no:financial:transact
  - no:pii

model:
  provider: "anthropic"
  model_id: "claude-sonnet-4"

contact:
  name: "Alice"
  url: "https://github.com/alice/research-assistant"
```

## License

Apache License 2.0 — see [LICENSE](./LICENSE). Versions before 1.5.1 were released under MIT.

## Inputs

| Input | Default | |
|---|---|---|
| `file-path` | `PROVENANCE.yml` | Where the declaration is |
| `fail-on-error` | `true` | Fail the build on validation errors |
| `verify-signature` | `true` | Cryptographically verify `identity.signature` when present |
| `require-signature` | `false` | Fail when the declaration carries no signature at all |
| `check-repository` | `true` | Check `provenance_id` names the repository this runs in |
| `check-code` | `warn` | Compare the declaration with the project on every build: `warn`, `suggest`, `automatic`, `strict` or `off` — see *Keeping the passport true*. |
| `signed-by` | `auto` | Who signs after an update: `service`, `developer` or `auto`. |
| `github-token` | the workflow token | Used to open the pull request in `suggest` mode. |

## Outputs

| Output | |
|---|---|
| `valid` | `true` / `false` |
| `errors` | Validation errors, newline separated |
| `signature` | `declaration` (spec 0.2 — whole file covered), `identity` (spec 0.1 — identity only), `invalid`, `none`, or `unchecked` |

## A note on spec versions

Under spec **0.2** a signature covers the whole declaration, so deleting a
constraint breaks it. Under **0.1** it covered only the identity and key — your
declared capabilities and constraints were not protected. Both validate here,
but a 0.1 file gets a warning saying so, and `signature` reports which coverage
was found.
