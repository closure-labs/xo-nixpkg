{ fetchYarnDeps }:

args:

fetchYarnDeps (
  args
  // {
    preBuild = (args.preBuild or "") + ''
      source ${./retry-yarn-fetch.sh}
    '';

    # fuse-shared-library-linux ships helper scripts with setuid/setgid bits.
    # Normalize those tarballs in the fixed-output cache so Yarn can unpack
    # them in Nix sandboxes without a global Node chmod monkey patch.
    postBuild = (args.postBuild or "") + ''
      bash ${./normalize-yarn-cache.sh} "$out"
    '';
  }
)
