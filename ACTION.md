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
| `version` | `latest` | PXTA release tag to use. |

Outputs: `result` (`pass` or `fail`), `exit-code` (0 pass, 1 rule broken,
2 usage or rules error, 3 audit could not run) and `report` (the folder).
A usage error or a failed audit always fails the step, whatever `fail` says.

The rules file format is in the README under "pxta check".

## The pattern, for other SoftDevStudio.com projects

Every project with a CI use gets its action the same way:

1. `action.yml` in the code repo's root, `runs: using: composite`, so users
   write `uses: <org>/<repo>@vX.Y.Z` and no Docker image is needed.
2. Install step: map `RUNNER_OS`/`RUNNER_ARCH` to the release archive name
   (the archives carry no version, so `releases/latest/download` works),
   download it and `SHA256SUMS`, refuse on a mismatch, print the version.
   A `<tool>-path` input skips the download so the repo's own tests can run
   the action against a binary built from the commit.
3. Run step: build the argument list as a bash array from inputs passed
   through `env:` (never interpolate inputs into the script), let the tool
   print `::error`/`::warning` annotations and append Markdown to
   `$GITHUB_STEP_SUMMARY`, record the exit code as an output and exit 0.
4. Upload step with `if: always()`, so the evidence survives a failure.
5. Verdict step: exit non-zero for a broken rule only when `fail` is true;
   usage errors and tool failures always fail.
6. `.github/workflows/action-test.yml` runs the action with `uses: ./` on
   every OS the project ships for, on inputs that must pass and inputs that
   must fail, and checks the outputs. A `download` job, started by hand
   after a release, runs it against the published binaries.
