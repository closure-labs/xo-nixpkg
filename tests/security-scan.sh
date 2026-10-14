#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
mkdir -p "$temporary/bin" "$temporary/protector"
export FAKE_SECURITY_ROOT="$root" FAKE_SECURITY_FIXTURE="$temporary"
export FAKE_SECURITY_REAL_CP
FAKE_SECURITY_REAL_CP=$(command -v cp)
export PYTHONDONTWRITEBYTECODE=1
python3 - "$root" "$temporary" <<'PYTHON'
import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location("fixture",Path(sys.argv[1])/"tests/security-normalize.py")
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
expected,inventory=fixture.supply(Path(sys.argv[2])/"protector")
Path(sys.argv[2],"expected.json").write_text(json.dumps(expected))
Path(sys.argv[2],"raw.json").write_text(json.dumps(fixture.report(inventory)))
PYTHON
cat >"$temporary/bin/nix" <<'NIX'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_SECURITY_FIXTURE/nix-calls"
[[ $* == *'#supply-protector-latest'* ]]
case $1 in
  build) printf '/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-protector\n' ;;
  eval) cat "$FAKE_SECURITY_FIXTURE/expected.json" ;;
  *) exit 1 ;;
esac
NIX
cat >"$temporary/bin/cp" <<'CP'
#!/usr/bin/env bash
set -euo pipefail
source=${1/\/nix\/store\/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-protector/$FAKE_SECURITY_FIXTURE/protector}
exec "$FAKE_SECURITY_REAL_CP" "$source" "$2"
CP
cat >"$temporary/bin/grype" <<'GRYPE'
#!/usr/bin/env bash
set -euo pipefail
[[ $GRYPE_DB_MAX_ALLOWED_BUILT_AGE == 24h && $GRYPE_DB_VALIDATE_AGE == true ]]
[[ $GRYPE_DB_CACHE_DIR == */xo-security.*/grype-db ]]
printf '%s\n' "$*" >>"$FAKE_SECURITY_FIXTURE/grype-calls"
[[ ${FAKE_SCANNER_FAILURE:-false} != true ]] || exit 2
case $1 in
  version) printf '{"version":"fixture"}\n' ;;
  *scanner-check.cdx.json)
    if [[ ${FAKE_CANARY_EMPTY:-false} == true ]]; then printf '{"matches":[]}\n'; else
      printf '{"matches":[{"artifact":{"name":"openssl"}},{"artifact":{"name":"lodash"}}]}\n'
    fi ;;
  *) cat "$FAKE_SECURITY_FIXTURE/raw.json" ;;
esac
GRYPE
cat >"$temporary/bin/xo-nixpkg-security-applicability" <<'ENGINE'
#!/usr/bin/env bash
set -euo pipefail
exec python3 "$FAKE_SECURITY_ROOT/nix/security-applicability.py" "$@"
ENGINE
cat >"$temporary/normalize.py" <<'NORMALIZE'
import runpy,sys,os
if sys.argv[1] == "verify":
    sys.argv[2] = os.environ["FAKE_SECURITY_FIXTURE"] + "/protector"
runpy.run_path(os.environ["FAKE_SECURITY_ROOT"] + "/nix/security-normalize.py",run_name="__main__")
NORMALIZE
sed -i "1c#!${BASH}" "$temporary/bin/"*
chmod +x "$temporary/bin/"*
export PATH="$temporary/bin:$PATH"
export XO_NIXPKG_SOURCE_ROOT="$root" XO_SECURITY_NORMALIZE_SOURCE="$temporary/normalize.py"
export XO_SECURITY_APPLICABILITY_RULES="$root/nix/security-applicability-rules.json"
export SECURITY_OUTPUT="$temporary/report"
bash "$root/ci/security-scan.sh" latest
jq -e '.mode == "report" and .total == 2 and .unresolved_critical == 2 and .reviewed == 0' "$SECURITY_OUTPUT/summary.json" >/dev/null
jq -e 'length == 2' "$SECURITY_OUTPUT/unresolved-critical.json" >/dev/null
[[ $(wc -l <"$temporary/nix-calls") == 2 && $(wc -l <"$temporary/grype-calls") == 3 ]]
reject() {
  if "$@" >"$temporary/rejected.log" 2>&1; then echo "Accepted invalid scan invocation: $*" >&2; exit 1; fi
}
SECURITY_MODE=enforce reject bash "$root/ci/security-scan.sh" latest
[[ -s $SECURITY_OUTPUT/unresolved-critical.json ]]
FAKE_SCANNER_FAILURE=true reject bash "$root/ci/security-scan.sh" latest
[[ ! -e $SECURITY_OUTPUT/critical-applicability.json && ! -e $SECURITY_OUTPUT/summary.json ]]
FAKE_CANARY_EMPTY=true reject bash "$root/ci/security-scan.sh" latest
[[ ! -e $SECURITY_OUTPUT/critical-applicability.json ]]
printf 'tampered\n' >>"$temporary/protector/xen-orchestra.cdx.json"
before=$(wc -l <"$temporary/grype-calls")
reject bash "$root/ci/security-scan.sh" latest
[[ $(wc -l <"$temporary/grype-calls") == "$before" ]]
before=$(wc -l <"$temporary/nix-calls")
reject bash "$root/ci/security-scan.sh" nonexistent
reject bash "$root/ci/security-scan.sh" latest stable
[[ $(wc -l <"$temporary/nix-calls") == "$before" ]]
echo 'Security scan failure, canary, channel and report-mode fixtures passed'
