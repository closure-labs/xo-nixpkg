{
  channel,
  package,
  pkgs,
  sourceRev,
  sourceTimestamp,
  version,
}:

let
  spdxSchema = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json";
    hash = "sha256-I5IIt6woezz12amvI/nWmGOXEQKl4Vh6J6OYtDSQuJs=";
  };
  cyclonedxSchema = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/bom-1.5.schema.json";
    hash = "sha256-Bn94JLCGU4OeoFCungnKSDdercJlKw4qKZR259uQM1s=";
  };
  cyclonedxJsfSchema = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/CycloneDX/specification/1.5/schema/jsf-0.82.schema.json";
    hash = "sha256-i64ALCXnI9t+4fJq/eaArhorGo9rS0sP1l3DvssJCq4=";
  };
in
pkgs.runCommand "xo-${channel}-supply-protector-${version}"
  {
    nativeBuildInputs = with pkgs; [
      check-jsonschema
      coreutils
      jq
    ];
    exportReferencesGraph = [
      "closure"
      package
    ];
    ROOT_PATH = package;
    CHANNEL = channel;
    VERSION = version;
    SOURCE_REV = sourceRev;
    SOURCE_TIMESTAMP = toString sourceTimestamp;
    CACHE_URL = "https://xen-orchestra-ce.cachix.org";
    CACHE_PUBLIC_KEY = "xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E=";
    SPDX_SCHEMA = spdxSchema;
    CYCLONEDX_SCHEMA = cyclonedxSchema;
    CYCLONEDX_JSF_SCHEMA = cyclonedxJsfSchema;
    passthru = {
      protectedPackage = package;
      inherit channel sourceRev version;
    };
    meta.description = "Reproducible closure assertion and SBOMs for Xen Orchestra ${channel}";
  }
  ''
    bash ${./supply-protector.sh} closure "$out"
  ''
