{ lib }:

let
  pins = {
    xenOrchestra = builtins.fromJSON (builtins.readFile ./sources/xen-orchestra.json);
    libvhdi = builtins.fromJSON (builtins.readFile ./sources/libvhdi.json);
  };
  isHash = value: builtins.isString value && lib.hasPrefix "sha256-" value;
  xo = pins.xenOrchestra;
  vhdi = pins.libvhdi;
in
assert lib.assertMsg (
  xo.schemaVersion == 1
  && xo.owner == "vatesfr"
  && xo.repo == "xen-orchestra"
  && builtins.match "[0-9]+(\\.[0-9]+)+" xo.version != null
  && builtins.match "[a-f0-9]{40}" xo.rev != null
  && isHash xo.hash
  && isHash xo.yarnHash
  && isHash xo.docsYarnHash
  && builtins.isAttrs xo.platformTools
) "invalid Xen Orchestra source-lock contract";
assert lib.assertMsg (
  vhdi.schemaVersion == 1
  && vhdi.type == "Url"
  && vhdi.unpack == true
  && builtins.match "[0-9]{8}" vhdi.version != null
  && lib.hasSuffix "/libvhdi-alpha-${vhdi.version}.tar.gz" vhdi.url
  && isHash vhdi.hash
) "invalid libvhdi source-lock contract";
pins
