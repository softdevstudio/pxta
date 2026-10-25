#!/usr/bin/env bash
# Runs every test, including the browser tests against the fixture sites,
# and records the output in test/results. It also writes the sample report
# gallery to test/results/gallery. Every number on pxta.com comes from these
# files. Needs Chrome, Chromium or Edge.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
res="$root/test/results"
rm -rf "$res"
mkdir -p "$res/gallery"
cd "$root"

browser=$(go run ./scripts/findbrowser 2>/dev/null || echo "none found")
{
  echo "recorded: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "machine: $(uname -srm)"
  echo "cpus: $(getconf _NPROCESSORS_ONLN 2>/dev/null || echo ?)"
  echo "go: $(go version)"
  echo "pxta: $(cat VERSION)"
  echo "browser: $browser"
} > "$res/environment.txt"
cat "$res/environment.txt"

echo "== all tests (unit and browser)"
PXTA_REQUIRE_BROWSER=1 PXTA_RECORD_DIR="$res" PXTA_CRASH_PAGES="${PXTA_CRASH_PAGES:-500}" \
  go test -count=1 -v -timeout 150m ./... 2>&1 | grep -v 'TLS handshake error' > "$res/tests.txt" || true
grep -E "^(--- |ok|FAIL)" "$res/tests.txt" | grep -v "^--- PASS" || true
if grep -qE "^(--- FAIL|FAIL)" "$res/tests.txt"; then echo "::error::tests failed"; exit 1; fi
echo "passed: $(grep -c '^\s*--- PASS' "$res/tests.txt") tests and subtests, $(grep -c '^\s*--- SKIP' "$res/tests.txt") skipped"
cat "$res/crash-recovery.txt"

echo "== sample report gallery"
PXTA_REQUIRE_BROWSER=1 PXTA_GALLERY_DIR="$res/gallery" go test -count=1 -run '^TestGallery$' -timeout 30m . > /dev/null
python3 - "$res/gallery" > "$res/gallery.txt" <<'PY'
import json, os, sys
d = sys.argv[1]
for name in sorted(os.listdir(d)):
    j = json.load(open(os.path.join(d, name, "findings.json")))
    c = j.get("counts", {})
    pages = len({p["page"] for p in j["pages"]})
    print(f"{name}: banner={j['banner'].get('platform') or 'none'} passes={','.join(j['passes'])} pages={pages} "
          f"high={c.get('high',0)} medium={c.get('medium',0)} low={c.get('low',0)} info={c.get('info',0)} "
          f"trackers={','.join(sorted(t['id'] for t in j['trackers']))}")
PY
cat "$res/gallery.txt"
echo "recorded in $res"
