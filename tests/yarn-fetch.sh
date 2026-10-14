#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin" "$temporary/work" "$temporary/attempts"
export TMPDIR="$temporary/attempts" FIXTURE="$temporary"
export PATH="$temporary/bin:$PATH"

# Emulate the upstream downloader: write the response before verifying it.
# Nix sandboxes have no /usr/bin/env; use the running toolchain interpreter.
printf '#!%s\n' "$BASH" >"$temporary/bin/prefetch-yarn-deps"
cat >>"$temporary/bin/prefetch-yarn-deps" <<'EOF'
set -euo pipefail
[[ $1 == --verbose && $2 == --builder && $3 == "$FIXTURE/yarn.lock" ]]
[[ -z $(ls -A) ]]
count=$(cat "$FIXTURE/count")
count=$((count + 1))
echo "$count" >"$FIXTURE/count"
if ((count <= FAILURES)); then
  printf 'corrupt response\n' >package.tgz
  touch partial-download
else
  printf 'verified archive\n' >package.tgz
fi
sha512sum --check "$FIXTURE/checksum" || exit 42
cp "$3" yarn.lock
EOF
chmod +x "$temporary/bin/prefetch-yarn-deps"
printf 'verified archive\n' >"$temporary/package.tgz"
(cd "$temporary" && sha512sum package.tgz >checksum)
printf 'unchanged upstream integrity\n' >"$temporary/yarn.lock"
# Avoid real backoff in fixtures; check that it stays bounded instead.
sleep() { [[ $1 == 5 || $1 == 10 ]]; }
# Checked separately by repository policy.
# shellcheck source=/dev/null
source "$root/nix/retry-yarn-fetch.sh"

for failures in 0 1 3; do
  export FAILURES=$failures
  echo 0 >"$temporary/count"
  rm -rf "$temporary/work"
  mkdir "$temporary/work"
  if (cd "$temporary/work" && prefetch-yarn-deps --verbose --builder "$temporary/yarn.lock"); then
    ((failures < 3))
    [[ $(cat "$temporary/count") == "$((failures + 1))" ]]
    cmp "$temporary/package.tgz" "$temporary/work/package.tgz"
    cmp "$temporary/yarn.lock" "$temporary/work/yarn.lock"
    [[ ! -e "$temporary/work/partial-download" ]]
  else
    status=$?
    [[ $status == 42 && $failures == 3 ]]
    [[ $(cat "$temporary/count") == 3 ]]
    [[ -z $(ls -A "$temporary/work") ]]
  fi
  [[ -z $(ls -A "$temporary/attempts") ]]
done
echo 'Yarn fetch retry fixtures passed'
