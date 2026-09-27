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
local check as `npx provenance-protocol check`. When the code has moved on (a new
version, a new AI provider, a new MCP server, a library implying a new
capability) you get a warning and the one command that fixes it:
`npx provenance-protocol check --update`. When the code clashes with a promise —
an email library while the passport says `no:write:email` — you are told, and the
promise is never changed for you. Set `check-code: strict` to fail the build
instead.

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

MIT

## Inputs

| Input | Default | |
|---|---|---|
| `file-path` | `PROVENANCE.yml` | Where the declaration is |
| `fail-on-error` | `true` | Fail the build on validation errors |
| `verify-signature` | `true` | Cryptographically verify `identity.signature` when present |
| `require-signature` | `false` | Fail when the declaration carries no signature at all |
| `check-repository` | `true` | Check `provenance_id` names the repository this runs in |
| `check-code` | `suggest` | Compare the declaration with the project on every build. `suggest` warns when the passport is out of date or the code clashes with a promise; `strict` fails the build; `off` skips it. Read locally — nothing is sent anywhere. |

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
