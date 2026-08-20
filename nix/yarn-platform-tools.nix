{ lib, yarnLock }:

let
  lines = lib.splitString "\n" (builtins.readFile yarnLock);
  findVersion =
    package:
    let
      state =
        lib.foldl'
          (
            acc: line:
            if acc.version != null then
              acc
            else if lib.hasPrefix "\"${package}@" line || lib.hasPrefix "${package}@" line then
              {
                inEntry = true;
                version = null;
              }
            else if acc.inEntry && lib.hasPrefix "  version \"" line then
              {
                inEntry = false;
                version = lib.removeSuffix "\"" (lib.removePrefix "  version \"" line);
              }
            else if acc.inEntry && line == "" then
              {
                inEntry = false;
                version = null;
              }
            else
              acc
          )
          {
            inEntry = false;
            version = null;
          }
          lines;
    in
    state.version;

  esbuildVersion = findVersion "@esbuild/linux-x64";
  turboVersion = findVersion "@turbo/linux-64";
  rollupVersion = findVersion "@rollup/rollup-linux-x64-gnu";
  tool =
    version: tarball: path: extra:
    if version == null then null else { inherit version tarball path; } // extra;
in
{
  x86_64-linux = {
    esbuild =
      tool esbuildVersion "_esbuild_linux_x64___linux_x64_${toString esbuildVersion}.tgz"
        "package/bin/esbuild"
        { };
    turbo =
      tool turboVersion "_turbo_linux_64___linux_64_${toString turboVersion}.tgz"
        "turbo-linux-x64/bin/turbo"
        { };
    rollup =
      tool rollupVersion
        "_rollup_rollup_linux_x64_gnu___rollup_linux_x64_gnu_${toString rollupVersion}.tgz"
        "package/rollup.linux-x64-gnu.node"
        { packageBase = "linux-x64-gnu"; };
  };
  aarch64-linux = {
    esbuild =
      tool esbuildVersion "_esbuild_linux_arm64___linux_arm64_${toString esbuildVersion}.tgz"
        "package/bin/esbuild"
        { };
    turbo =
      tool turboVersion "_turbo_linux_arm64___linux_arm64_${toString turboVersion}.tgz"
        "turbo-linux-arm64/bin/turbo"
        { };
    rollup =
      tool rollupVersion
        "_rollup_rollup_linux_arm64_gnu___rollup_linux_arm64_gnu_${toString rollupVersion}.tgz"
        "package/rollup.linux-arm64-gnu.node"
        { packageBase = "linux-arm64-gnu"; };
  };
}
