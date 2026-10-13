{
  lib,
  fetchurl,
  nodejs_22,
  openssl_3_5,
}:
let
  # Node uses the LTS OpenSSL series, independently of pkgs.openssl.
  # Retain Nixpkgs' platform/certificate patches and remove this fallback when
  # its LTS package includes the September 2026 security release.
  openssl =
    if lib.versionAtLeast openssl_3_5.version "3.5.9" then
      openssl_3_5
    else
      assert openssl_3_5.version == "3.5.8";
      openssl_3_5.overrideAttrs (_: {
        version = "3.5.9";
        src = fetchurl {
          url = "https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz";
          hash = "sha256-YD9WAuLu8A13+9Qp003NWCK7MBdXobyc2yTGcPHrhZo=";
        };
      });
in
{
  inherit openssl;
  nodejs = nodejs_22.override { inherit openssl; };
}
