#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0
#
# check_spdx.sh — license-header guard. FAILS (exit 1) if any tracked *.py file under
# glyph_relay/ or tests/ is missing the Elastic License 2.0 SPDX tag in its first 3
# lines. Run by CI (.github/workflows/ci.yml) and locally before a PR. Stdlib bash +
# git only (no pip, no Python import) — mirrors glyph-client's add_spdx.py --check.
#
# Why "first 3 lines": Python files lead with an optional shebang and/or an encoding
# cookie, so the SPDX comment may be line 1, 2, or 3. We scan that window only so a
# stray "SPDX-License-Identifier" appearing in a docstring body cannot mask a real
# missing header.
set -uo pipefail
cd "$(dirname "$0")/.."

TAG='SPDX-License-Identifier: Elastic-2.0'
missing=0

# Only tracked files (git ls-files), scoped to the two source trees the task pins.
# -z / read -d keeps paths with odd characters intact.
while IFS= read -r -d '' f; do
  if ! head -n 3 "$f" | grep -qF "$TAG"; then
    printf '\033[31mSPDX MISSING\033[0m %s\n' "$f" >&2
    missing=1
  fi
done < <(git ls-files -z 'glyph_relay/*.py' 'tests/*.py')

if [ "$missing" -ne 0 ]; then
  echo >&2
  echo "SPDX check FAILED — add '# ${TAG}' within the first 3 lines of each file above." >&2
  exit 1
fi
echo "check_spdx: clean — every tracked glyph_relay/ + tests/ *.py carries the Elastic-2.0 tag."
