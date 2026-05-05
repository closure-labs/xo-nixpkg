{ fetchYarnDeps }:

args:

fetchYarnDeps (
  args
  // {
    # fuse-shared-library-linux ships helper scripts with setuid/setgid bits.
    # Normalize those tarballs in the fixed-output cache so Yarn can unpack
    # them in Nix sandboxes without a global Node chmod monkey patch.
    postBuild = (args.postBuild or "") + ''
      set -euo pipefail

      rewriteResolvedHash() {
        local tarball="$1"
        local url="$2"
        local entryPattern="$3"
        local newHash

        if ! grep -Fq "$url#" "$out/yarn.lock"; then
          echo "ERROR: cannot find yarn.lock entry for $url" >&2
          exit 1
        fi

        newHash="$(sha1sum "$tarball")"
        newHash="''${newHash%% *}"
        sed -i \
          -e "s|$url#[0-9a-f]\{40\}|$url#$newHash|" \
          -e "/$entryPattern/,/^$/ { /^  integrity /d; }" \
          "$out/yarn.lock"
      }

      for tarball in "$out"/fuse_shared_library_linux*.tgz; do
        [ -e "$tarball" ] || continue

        case "$(basename "$tarball")" in
          fuse_shared_library_linux___fuse_shared_library_linux_1.0.1.tgz)
            url="https://registry.yarnpkg.com/fuse-shared-library-linux/-/fuse-shared-library-linux-1.0.1.tgz"
            entryPattern="^fuse-shared-library-linux@\^1\.0\.1:"
            ;;
          fuse_shared_library_linux_arm___fuse_shared_library_linux_arm_1.0.0.tgz)
            url="https://registry.yarnpkg.com/fuse-shared-library-linux-arm/-/fuse-shared-library-linux-arm-1.0.0.tgz"
            entryPattern="^fuse-shared-library-linux-arm@\^1\.0\.0:"
            ;;
          *)
            continue
            ;;
        esac

        if ! tar -tvf "$tarball" | grep -Eq "^...[sS]|^......[sS]"; then
          continue
        fi

        tmpDir="$(mktemp -d)"
        tar -xzf "$tarball" -C "$tmpDir"
        chmod -R u-s,g-s "$tmpDir"
        tar \
          --sort=name \
          --mtime="@0" \
          --owner=0 \
          --group=0 \
          --numeric-owner \
          --pax-option=delete=atime,delete=ctime \
          -cf - \
          -C "$tmpDir" package \
          | gzip -n > "$tarball.tmp"
        mv "$tarball.tmp" "$tarball"
        rm -rf "$tmpDir"
        rewriteResolvedHash "$tarball" "$url" "$entryPattern"
      done
    '';
  }
)
