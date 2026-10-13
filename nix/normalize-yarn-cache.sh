#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cache=$1
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT

for tarball in "$cache"/fuse_shared_library_linux*.tgz; do
  [[ -e $tarball ]] || continue
  case "$(basename "$tarball")" in
    fuse_shared_library_linux___fuse_shared_library_linux_1.0.1.tgz)
      url='https://registry.yarnpkg.com/fuse-shared-library-linux/-/fuse-shared-library-linux-1.0.1.tgz'
      entry='^fuse-shared-library-linux@\^1\.0\.1:'
      ;;
    fuse_shared_library_linux_arm___fuse_shared_library_linux_arm_1.0.0.tgz)
      url='https://registry.yarnpkg.com/fuse-shared-library-linux-arm/-/fuse-shared-library-linux-arm-1.0.0.tgz'
      entry='^fuse-shared-library-linux-arm@\^1\.0\.0:'
      ;;
    *) continue ;;
  esac

  # Check tar separately: grep -q in a pipe can SIGPIPE tar, and a failed
  # archive read must never be interpreted as absence of privileged modes.
  tar -tvf "$tarball" >"$temporary/listing"
  if ! grep -Eq '^...[sS]|^......[sS]' "$temporary/listing"; then
    continue
  fi
  grep -Fq "$url#" "$cache/yarn.lock"
  grep -q "$entry" "$cache/yarn.lock"
  mkdir "$temporary/package-root"
  tar -xzf "$tarball" -C "$temporary/package-root"
  chmod -R u-s,g-s "$temporary/package-root"
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --pax-option=delete=atime,delete=ctime -cf - \
    -C "$temporary/package-root" package | gzip -n >"$temporary/archive.tgz"
  tar -tvf "$temporary/archive.tgz" >"$temporary/listing"
  if grep -Eq '^...[sS]|^......[sS]' "$temporary/listing"; then
    echo "Privileged modes remain in normalized archive: $tarball" >&2
    exit 1
  fi
  mv "$temporary/archive.tgz" "$tarball"
  new_hash=$(sha1sum "$tarball")
  new_hash=${new_hash%% *}
  sed -i -e "s|$url#[0-9a-f]\{40\}|$url#$new_hash|" \
    -e "/$entry/,/^$/ { /^  integrity /d; }" "$cache/yarn.lock"
  grep -Fq "$url#$new_hash" "$cache/yarn.lock"
  rm -rf "$temporary/package-root"
done
