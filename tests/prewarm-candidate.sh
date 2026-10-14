#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin"
export XO_NIXPKG_SOURCE_ROOT="$root" XO_NIXPKG_CI_EVIDENCE="$temporary/evidence"
export FAKE_PREWARM_DIR="$temporary" XO_NIXPKG_CACHIX_CACHE_NAME=fixture CACHIX_AUTH_TOKEN=fixture
export GITHUB_ACTIONS=true DEFAULT_BRANCH=main GITHUB_REPOSITORY=example/xo-nixpkg
export GITHUB_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa GITHUB_REF=refs/heads/main GITHUB_EVENT_NAME=workflow_dispatch
cat >"$temporary/bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *'rev-parse HEAD') printf '%s\n' "$GITHUB_SHA" ;;
  *'diff --name-only HEAD') printf '%s\n' "${FAKE_DIRTY_PATH:-}" ;;
  *) exit 1 ;;
esac
SH
cat >"$temporary/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'api repos/example/xo-nixpkg/branches/main' ]]
jq -n --arg sha "$GITHUB_SHA" --argjson protected "${FAKE_PROTECTED:-true}" '{protected:$protected,commit:{sha:$sha}}'
SH
cat >"$temporary/bin/flake-plan-runner" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
plan= manifest= timings=
while (($#)); do
  case $1 in
    --plan-file) plan=$2;shift 2 ;;
    --manifest) manifest=$2;shift 2 ;;
    --timings) timings=$2;shift 2 ;;
    *) shift ;;
  esac
done
cp "$plan" "$FAKE_PREWARM_DIR/plan.json"
jq '{schemaVersion:2,plan:.name,targetCount:(.targets|length),failureCount:0,
  results:[.targets[]|{name,attribute,status:"success",outputs:[("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-"+.name)]}]}' "$plan" >"$manifest"
printf '{}\n' >"$timings"
SH
cat >"$temporary/bin/nix" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  'eval --accept-flake-config')
    target=${*: -1}; name=${target##*.}; name=${target%.outPath}; name=${name##*.}
    [[ $name == latest || $name == stable ]] && name=xo-$name
    printf '/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-%s\n' "${FAKE_OUTPUT_NAME:-$name}"
    ;;
  'path-info --recursive') printf '%s\n' /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dependency "$3" ;;
  *) exit 1 ;;
esac
SH
cat >"$temporary/bin/cachix" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1 $2" == 'push fixture' ]]
printf '%s\n' "${@:3}" >"$FAKE_PREWARM_DIR/pushed"
SH
sed -i "1c#!${BASH}" "$temporary/bin/"*
chmod +x "$temporary/bin/"*
export PATH="$temporary/bin:$PATH"
bash "$root/ci/prewarm-candidate.sh" release latest,stable "$temporary/output"
jq -e '[.targets[].name]==["xo-latest","supply-protector-latest","xo-stable","supply-protector-stable"]' "$temporary/plan.json" >/dev/null
[[ $(wc -l <"$temporary/pushed") == 4 ]]
bash "$root/ci/prewarm-candidate.sh" runtime
jq -e '.targets==[{name:"runtime-node",attribute:"packages.x86_64-linux.runtime-node"}]' "$temporary/plan.json" >/dev/null
[[ $(wc -l <"$temporary/pushed") == 1 ]]
reject() {
  rm -f "$temporary/plan.json" "$temporary/pushed"
  if "$@" >"$temporary/rejected.log" 2>&1; then echo 'Invalid privileged prewarm accepted' >&2;exit 1;fi
  [[ ! -e $temporary/pushed ]]
}
GITHUB_REF=refs/pull/2/merge reject bash "$root/ci/prewarm-candidate.sh" runtime
[[ ! -e $temporary/plan.json ]]
GITHUB_EVENT_NAME=pull_request reject bash "$root/ci/prewarm-candidate.sh" runtime
[[ ! -e $temporary/plan.json ]]
FAKE_PROTECTED=false reject bash "$root/ci/prewarm-candidate.sh" runtime
[[ ! -e $temporary/plan.json ]]
FAKE_DIRTY_PATH=ci/prewarm-candidate.sh reject bash "$root/ci/prewarm-candidate.sh" runtime
[[ ! -e $temporary/plan.json ]]
FAKE_DIRTY_PATH=flake.nix reject bash "$root/ci/prewarm-candidate.sh" runtime
[[ ! -e $temporary/plan.json ]]
FAKE_OUTPUT_NAME=unexpected reject bash "$root/ci/prewarm-candidate.sh" runtime
reject bash "$root/ci/prewarm-candidate.sh" release rolling
reject bash "$root/ci/prewarm-candidate.sh" release latest,latest
printf 'Trusted candidate prewarm fixtures passed\n'
