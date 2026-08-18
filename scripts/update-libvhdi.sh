# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash

set -euo pipefail

repository_root=${LIBVHDI_REPOSITORY_ROOT:-$PWD}
pin_file=${LIBVHDI_PIN_FILE:-$repository_root/nix/sources/libvhdi.json}
releases_file=${LIBVHDI_RELEASES_JSON:-}
prefetch_file=${LIBVHDI_PREFETCH_JSON:-}

if [[ ! -f $pin_file ]]; then
  printf 'libvhdi source lock does not exist: %s\n' "$pin_file" >&2
  exit 1
fi

if [[ $(jq -er .schemaVersion "$pin_file") != 1 ]]; then
  printf 'Expected libvhdi source-lock schema 1 in %s\n' "$pin_file" >&2
  exit 1
fi

current_version=$(jq -er '.version | select(test("^[0-9]{8}$"))' "$pin_file")

temporary_releases=
cleanup() {
  [[ -z $temporary_releases ]] || rm -f "$temporary_releases"
}
trap cleanup EXIT

if [[ -z $releases_file ]]; then
  temporary_releases=$(mktemp)
  curl_args=(
    --fail
    --location
    --silent
    --show-error
    --header 'Accept: application/vnd.github+json'
    --header 'X-GitHub-Api-Version: 2022-11-28'
  )
  if [[ -n ${GITHUB_TOKEN:-} ]]; then
    curl_args+=(--header "Authorization: Bearer $GITHUB_TOKEN")
  fi
  curl "${curl_args[@]}" \
    'https://api.github.com/repos/libyal/libvhdi/releases?per_page=100' \
    --output "$temporary_releases"
  releases_file=$temporary_releases
fi

latest_release=$(jq -cer '
  [
    .[]
    | select(.draft == false)
    | select(.tag_name | type == "string")
    | select(.tag_name | test("^[0-9]{8}$"))
  ]
  | if length == 0 then error("no numeric date releases found") else max_by(.tag_name | tonumber) end
' "$releases_file")
latest_version=$(jq -er .tag_name <<<"$latest_release")

asset_name="libvhdi-alpha-${latest_version}.tar.gz"
asset_urls=$(jq -cer --arg asset "$asset_name" '[.assets[]? | select(.name == $asset) | .browser_download_url]' <<<"$latest_release")
if [[ $(jq -r length <<<"$asset_urls") != 1 ]]; then
  printf 'Release %s must contain exactly one %s asset\n' "$latest_version" "$asset_name" >&2
  exit 1
fi
asset_url=$(jq -er '.[0] | select(type == "string" and startswith("https://github.com/libyal/libvhdi/releases/download/"))' <<<"$asset_urls")

if (( 10#$latest_version < 10#$current_version )); then
  printf 'Refusing to downgrade libvhdi from %s to %s\n' "$current_version" "$latest_version" >&2
  exit 1
fi
if [[ $latest_version == "$current_version" ]]; then
  printf 'libvhdi %s is already current\n' "$current_version"
  exit 0
fi

if [[ -n $prefetch_file ]]; then
  prefetch_output=$(<"$prefetch_file")
else
  prefetch_output=$(nix store prefetch-file --json --unpack "$asset_url")
fi
new_hash=$(jq -er '.hash | select(type == "string" and startswith("sha256-"))' <<<"$prefetch_output")

pin_directory=$(dirname "$pin_file")
temporary_pin=$(mktemp "$pin_directory/.sources.json.XXXXXX")
trap 'rm -f "$temporary_pin"; cleanup' EXIT
jq \
  --arg hash "$new_hash" \
  --arg url "$asset_url" \
  --arg version "$latest_version" '
    .type = "Url" |
    .url = $url |
    .unpack = true |
    .version = $version |
    .hash = $hash
  ' "$pin_file" >"$temporary_pin"
jq -e '.schemaVersion == 1 and (.version | test("^[0-9]{8}$"))' "$temporary_pin" >/dev/null
mv "$temporary_pin" "$pin_file"
trap cleanup EXIT

printf 'Updated libvhdi from %s to %s (%s)\n' "$current_version" "$latest_version" "$new_hash"
