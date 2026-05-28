{
  x86_64-linux = {
    esbuild = {
      version = "0.25.12";
      tarball = "_esbuild_linux_x64___linux_x64_0.25.12.tgz";
      path = "package/bin/esbuild";
    };
    turbo = {
      version = "2.9.6";
      tarball = "_turbo_linux_64___linux_64_2.9.6.tgz";
      path = "turbo-linux-x64/bin/turbo";
    };
    rollup = {
      version = "4.60.1";
      tarball = "_rollup_rollup_linux_x64_gnu___rollup_linux_x64_gnu_4.60.1.tgz";
      path = "package/rollup.linux-x64-gnu.node";
      packageBase = "linux-x64-gnu";
    };
  };
  aarch64-linux = {
    esbuild = {
      version = "0.25.12";
      tarball = "_esbuild_linux_arm64___linux_arm64_0.25.12.tgz";
      path = "package/bin/esbuild";
    };
    turbo = {
      version = "2.9.6";
      tarball = "_turbo_linux_arm64___linux_arm64_2.9.6.tgz";
      path = "turbo-linux-arm64/bin/turbo";
    };
    rollup = {
      version = "4.60.1";
      tarball = "_rollup_rollup_linux_arm64_gnu___rollup_linux_arm64_gnu_4.60.1.tgz";
      path = "package/rollup.linux-arm64-gnu.node";
      packageBase = "linux-arm64-gnu";
    };
  };
}
