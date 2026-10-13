#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT

if [[ ${1:-} == --verify ]]; then
  cache=$2
  for tarball in "$cache"/fuse_shared_library_linux*.tgz; do
    [[ -e $tarball ]] || continue
    tar -tvf "$tarball" >"$temporary/listing"
    if grep -Eq '^...[sS]|^......[sS]' "$temporary/listing"; then
      echo "Privileged modes in production cache: $tarball" >&2
      exit 1
    fi
    hash=$(sha1sum "$tarball"); hash=${hash%% *}
    grep -Fq "#$hash\"" "$cache/yarn.lock"
  done
  echo 'Production FUSE cache verified'
  exit
fi

prepare() {
  local cache=$1 name version filename hash
  mkdir -p "$cache"
  : >"$cache/yarn.lock"
  for name in fuse-shared-library-linux fuse-shared-library-linux-arm; do
    version=1.0.1
    [[ $name != *-arm ]] || version=1.0.0
    filename=${name//-/_}___${name//-/_}_$version.tgz
    mkdir -p "$temporary/package"
    printf '{"name":"%s","version":"%s"}\n' "$name" "$version" >"$temporary/package/package.json"
    printf 'preserved payload\n' >"$temporary/package/helper"
    chmod 755 "$temporary/package/helper"
    # Early special bits and a large listing reproduce the short-read hazard.
    for i in {1..1000}; do : >"$temporary/package/file-$i"; done
    # Encode forbidden modes in archive metadata; the sandbox forbids chmod
    # setting those modes on real files, which is exactly what this tests.
    tar --mode=6755 -czf "$cache/$filename" -C "$temporary" package
    hash=$(sha1sum "$cache/$filename"); hash=${hash%% *}
    printf '%s@^%s:\n  version "%s"\n  resolved "https://registry.yarnpkg.com/%s/-/%s-%s.tgz#%s"\n  integrity sha512-stale\n\n' \
      "$name" "$version" "$version" "$name" "$name" "$version" "$hash" >>"$cache/yarn.lock"
    rm -rf "$temporary/package"
  done
  mkdir "$temporary/package"
  printf '{"name":"ordinary","version":"1.0.0"}\n' >"$temporary/package/package.json"
  tar -czf "$cache/ordinary.tgz" -C "$temporary" package
  hash=$(sha1sum "$cache/ordinary.tgz"); hash=${hash%% *}
  printf 'ordinary@1:\n  version "1.0.0"\n  resolved "https://registry.yarnpkg.com/ordinary/-/ordinary-1.0.0.tgz#%s"\n  integrity sha512-unchanged\n\n' "$hash" >>"$cache/yarn.lock"
  rm -rf "$temporary/package"
}

if [[ ${1:-} == --prepare ]]; then
  prepare "$2"
  if [[ -n ${3:-} ]]; then
    # Exercise the exact upstream archives as well as synthetic regressions.
    cp "$3" "$2/fuse_shared_library_linux___fuse_shared_library_linux_1.0.1.tgz"
    cp "$4" "$2/fuse_shared_library_linux_arm___fuse_shared_library_linux_arm_1.0.0.tgz"
    linux_hash=$(sha1sum "$3"); linux_hash=${linux_hash%% *}
    arm_hash=$(sha1sum "$4"); arm_hash=${arm_hash%% *}
    sed -i \
      -e "s|linux-1.0.1.tgz#[0-9a-f]*|linux-1.0.1.tgz#$linux_hash|" \
      -e "s|arm-1.0.0.tgz#[0-9a-f]*|arm-1.0.0.tgz#$arm_hash|" \
      -e '/^  integrity sha512-stale$/d' "$2/yarn.lock"
  fi
  bash "$root/nix/normalize-yarn-cache.sh" "$2"
  exit
fi

prepare "$temporary/original"
cp -R "$temporary/original" "$temporary/first"
cp -R "$temporary/original" "$temporary/second"
for cache in "$temporary/first" "$temporary/second"; do
  bash "$root/nix/normalize-yarn-cache.sh" "$cache"
  for tarball in "$cache"/fuse*.tgz; do
    tar -tvf "$tarball" >"$temporary/listing"
    if grep -Eq '^...[sS]|^......[sS]' "$temporary/listing"; then exit 1; fi
    [[ $(tar -xOf "$tarball" package/helper) == 'preserved payload' ]]
    grep -q '^-rwxr-xr-x.*package/helper$' "$temporary/listing"
    hash=$(sha1sum "$tarball"); hash=${hash%% *}
    grep -Fq "#$hash\"" "$cache/yarn.lock"
  done
  if grep -q 'sha512-stale' "$cache/yarn.lock"; then exit 1; fi
  grep -Fq 'integrity sha512-unchanged' "$cache/yarn.lock"
  cmp "$cache/ordinary.tgz" "$temporary/original/ordinary.tgz"
done
diff -r "$temporary/first" "$temporary/second"
bash "$root/nix/normalize-yarn-cache.sh" "$temporary/second"
diff -r "$temporary/first" "$temporary/second"

cp -R "$temporary/original" "$temporary/corrupt"
truncate -s 24 "$temporary/corrupt/fuse_shared_library_linux___fuse_shared_library_linux_1.0.1.tgz"
if bash "$root/nix/normalize-yarn-cache.sh" "$temporary/corrupt"; then
  echo 'Corrupt archive was accepted' >&2
  exit 1
fi

if [[ -n ${1:-} ]]; then
  # The check passes an immutable, normalized Nix-store mirror.
  mirror=$1
  mkdir "$temporary/install"
  cp "$mirror/yarn.lock" "$temporary/install/yarn.lock"
  chmod u+w "$temporary/install/yarn.lock"
  printf '%s\n' '{"private":true,"dependencies":{"fuse-shared-library-linux":"^1.0.1","fuse-shared-library-linux-arm":"^1.0.0"}}' >"$temporary/install/package.json"
  printf 'yarn-offline-mirror "%s"\n' "$mirror" >"$temporary/install/.yarnrc"
  # Nix's hook converts registry archive names to mirror-local file URLs.
  (cd "$temporary/install"
    fixup-yarn-lock yarn.lock
    yarn install --offline --frozen-lockfile --ignore-scripts --ignore-platform \
      --non-interactive --cache-folder "$temporary/yarn-cache")
fi
echo 'Yarn cache normalization fixtures passed'
