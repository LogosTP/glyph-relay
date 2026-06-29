#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0
#
# secret_scan.sh — committed-secret guard. FAILS (exit 1) if any TRACKED file looks
# like key material or a private env file. The repo .gitignore already excludes these
# (*.db, .env), so this is the CI backstop against a future `git add -f` mistake. Run
# by CI (.github/workflows/ci.yml) and locally before a PR. git + bash only.
#
# Two checks:
#   1) by filename — APNs auth keys (*.p8), PEM key/cert files (*.pem), SQLite history
#      databases (*.db), and real env files (.env / *.env, but NOT *.example templates).
#   2) by content  — PEM private-key banners inside any tracked file.
# This script excludes ITSELF from the content scan so its own grep patterns below do
# not self-trigger (same self-exclusion pattern as glyph-client's scrub-scan.sh).
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
note() { printf '\033[31mSECRET FAIL\033[0m %s\n' "$1" >&2; fail=1; }

# 1) Filename-based: any of these tracked is a committed secret. The ':!*.example'
#    pathspec keeps the committed `.env.example` template (no values) allowed.
while IFS= read -r -d '' f; do
  note "tracked secret-shaped file: ${f}"
done < <(git ls-files -z \
            '*.p8' '*.pem' '*.db' '.env' '*.env' \
            ':!*.example' ':!*.p8.example' ':!*.pem.example')

# 2) Content-based: a PEM private-key banner committed in any tracked file. Exclude
#    this script (it names the banners) so the guard never flags itself.
out=$(git grep -nE 'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY|BEGIN RSA' \
        -- ':!tools/secret_scan.sh' || true)
[ -n "$out" ] && note "PEM private-key banner in a tracked file:"$'\n'"$out"

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "Secret scan FAILED — remove the file from git (git rm --cached), rotate the secret, and confirm .gitignore covers it." >&2
  exit 1
fi
echo "secret_scan: clean — no committed key material or private env files."
