#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Dependencies may substitute only from cache.nixos.org. Product roots must build.
set -euo pipefail
options=(--option accept-flake-config false --option access-tokens ''
  --option substituters https://cache.nixos.org
  --option trusted-substituters https://cache.nixos.org
  --option extra-substituters '' --option builders ''
  --option sandbox true --option max-jobs 1 --option cores 2)
for target in xen-orchestra-ce libvhdi; do
  drv=$(nix path-info "${options[@]}" --derivation --no-write-lock-file ".#$target")
  [[ $drv =~ ^/nix/store/[a-z0-9]{32}-[^/]+\.drv$ ]]
  # Materialize public dependencies first. This does not realize the product drv.
  dependency_list=$(nix-store --query --references "$drv")
  if [[ -n $dependency_list ]]; then
    mapfile -t dependencies <<<"$dependency_list"
    nix-store "${options[@]}" --realise "${dependencies[@]}" >/dev/null
  fi
  # A fresh runner must not have these custom product outputs already present.
  output_list=$(nix-store --query --outputs "$drv")
  test -n "$output_list"
  mapfile -t outputs <<<"$output_list"
  for output in "${outputs[@]}"; do
    test ! -e "$output"
  done
  # No substitute is allowed for the root itself. All inputs were realized above.
  nix-store "${options[@]}" --option substitute false --realise "$drv" >/dev/null
  for output in "${outputs[@]}"; do
    nix-store --check-validity "$output"
  done
  printf 'Source smoke passed for %s\n' "$target"
done
