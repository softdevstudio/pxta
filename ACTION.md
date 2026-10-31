# The PXTA GitHub Action

`action.yml` in this repo is a composite action: it downloads a PXTA release
for the runner, checks it against the release's SHA256SUMS, runs
`pxta check`, writes the result to the job summary, turns each broken rule
into an annotation and uploads the report.

## Use it

```yaml
name: Tracking check
on:
  schedule: [{ cron: "17 6 * * 1" }]
  workflow_dispatch:
jobs:
  pxta:
    runs-on: ubuntu-latest   # has Chrome; macOS runners do too
    steps:
      - uses: actions/checkout@v4          # only needed for a rules file in the repo
      - uses: softdevstudio/pxta@v0.2.0
        with:
          url: https://www.example.com/
          rules: pxta-rules.json           # optional
```

| Input | Default | What it does |
|---|---|---|
| `url` | | Site to audit. |
| `findings` | | Judge a saved `findings.json` instead of auditing (no browser needed). |
| `rules` | | Rules file; empty uses the defaults (fail on medium and above, and on a banner PXTA could not answer). |
| `pages` | `20` | Most pages to visit. |
| `passes` | `none,reject,accept` | Consent passes to run. |
| `redact` | `true` | Replace personal values in the report with REDACTED before it is uploaded. |
| `args` | | More `pxta check` options, such as `--ignore-robots --depth 2`. |
| `out` | `pxta-report` | Report folder. |
| `upload` | `true` | Upload the report folder as an artifact. |
| `artifact-name` | `pxta-report` | Artifact name. |
| `fail` | `true` | Fail the step when a rule is broken; `false` reports only. |
| `version` | | PXTA release tag to use, or `latest`. Empty runs the release the action is pinned to (`@v0.2.0` runs pxta 0.2.0); a branch or SHA pin runs the latest. |
| `pxta-path` | | Use this pxta binary instead of downloading one (for testing the action). |

Outputs: `result` (`pass` or `fail`), `exit-code` (0 pass, 1 rule broken,
2 usage or rules error, 3 audit could not run), `version` (the release that
ran) and `report` (the folder).
A usage error or a failed audit always fails the step, whatever `fail` says.

The artifact holds `report.html`, `findings.json`, `requests.har` and
`check.json`, and is uploaded only when the check finished (exit 0 or 1).
`redact` applies to audits the action runs; with `findings`, the file is
judged as it is and nothing is uploaded. Annotations, the job summary and
the job log never quote what the site sent: each problem is written from its
code, tracker, page path and pass, with queries cut and any path part that
looks like an address, a hash or an encoded value replaced. The full
sentences are in the report. Using the
action twice in one job needs a different `artifact-name` for each.

The rules file format is in the README under "pxta check".

## The pattern, for other SoftDevStudio.com projects

Every project with a CI use gets its action the same way:

1. `action.yml` in the code repo's root, `runs: using: composite`, so users
   write `uses: <org>/<repo>@vX.Y.Z` and no Docker image is needed.
2. Install step: default to the release the action is pinned to
   (`github.action_ref` when it is a vX.Y.Z tag), map `RUNNER_OS`/`RUNNER_ARCH` to the release archive name
   (the archives carry no version, so `releases/latest/download` works),
   download it and `SHA256SUMS`, refuse on a mismatch, print the version.
   A `<tool>-path` input skips the download so the repo's own tests can run
   the action against a binary built from the commit.
3. Run step: start with `set +e -uf` (the runner's bash has -e on, and a
   broken rule must not end the step before its exit code is recorded),
   build the argument list as a bash array from inputs passed through
   `env:` (never interpolate inputs into the script), let the tool
   print `::error`/`::warning` annotations and append Markdown to
   `$GITHUB_STEP_SUMMARY` when it is set (`${GITHUB_STEP_SUMMARY:-}`; it is
   unset on some self-hosted runners), record the exit code as an output and
   exit 0. Anything printed there is public to everyone who can read the
   run, so it is built from fixed fields, never from captured data.
4. Upload step with `if: always()` and the tool's exit code 0 or 1, listing
   the report files by name, so the evidence survives a broken rule and no
   working files go out.
5. Verdict step: exit non-zero for a broken rule only when `fail` is true;
   usage errors and tool failures always fail.
6. `.github/workflows/action-test.yml` runs the action with `uses: ./` on
   every OS the project ships for, on inputs that must pass and inputs that
   must fail, and checks the outputs. (PXTA's real-audit cases run on Linux
   and macOS; Windows runs the saved-findings cases.) A `download` job, started by hand
   after a release, runs it against the published binaries, unpinned and
   pinned to a tag, and checks the pinned binary's version.
