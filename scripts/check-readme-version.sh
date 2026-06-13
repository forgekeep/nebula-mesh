#!/usr/bin/env bash
# Fail when README.md pins an install VERSION older than the latest release tag.
#
# Closes the doc-rot gap from #227: the install snippets hardcode `VERSION=x.y.z`
# that nobody remembers to bump, so users copy-paste an outdated release that may
# lack published security fixes. This guard runs in CI and fails the build the
# moment a pin falls behind the newest tag. A pin equal to or ahead of the latest
# tag passes, so the release flow can bump README in the same PR that cuts the tag.
#
# Portable across BSD (macOS) and GNU (CI) sort: version compare uses numeric
# field sort, not `sort -V`.
set -euo pipefail

readme="${1:-README.md}"

latest_tag="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-version:refname | head -n1)"
if [ -z "${latest_tag:-}" ]; then
  echo "no release tags found; skipping README version check"
  exit 0
fi
latest="${latest_tag#v}"

pins="$(grep -oE 'VERSION=[0-9]+\.[0-9]+\.[0-9]+' "$readme" | sed 's/VERSION=//' | sort -u || true)"
if [ -z "${pins}" ]; then
  echo "no VERSION= pins found in ${readme}; nothing to check"
  exit 0
fi

# ver_lt A B -> exit 0 when A < B (strictly older).
ver_lt() {
  [ "$1" != "$2" ] &&
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -n1)" = "$1" ]
}

status=0
for p in ${pins}; do
  if ver_lt "$p" "$latest"; then
    echo "::error::README pins VERSION=${p}, older than latest release v${latest}"
    status=1
  else
    echo "ok: README pin ${p} >= latest release ${latest}"
  fi
done
exit "${status}"
