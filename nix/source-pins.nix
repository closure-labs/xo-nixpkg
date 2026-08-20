{ lib }:

let
  pins = {
    xenOrchestra = builtins.fromJSON (builtins.readFile ./sources/xen-orchestra.json);
    libvhdi = builtins.fromJSON (builtins.readFile ./sources/libvhdi.json);
  };
  isHash = value: builtins.isString value && lib.hasPrefix "sha256-" value;
  xo = pins.xenOrchestra;
  vhdi = pins.libvhdi;
  officialVersion = channel: builtins.match "[0-9]+(\\.[0-9]+)+" channel.version != null;
  rollingVersion =
    channel: builtins.match "unstable-[0-9]{4}-[0-9]{2}-[0-9]{2}" channel.version != null;
  validXoPin =
    channel:
    builtins.match "[a-f0-9]{40}" channel.rev != null
    && isHash channel.yarnHash
    && isHash channel.docsYarnHash;
in
assert lib.assertMsg (
  xo.schemaVersion == 2
  && xo.owner == "vatesfr"
  && xo.repo == "xen-orchestra"
  && builtins.isAttrs xo.channels
  &&
    builtins.attrNames xo.channels == [
      "latest"
      "rolling"
      "stable"
    ]
  && officialVersion xo.channels.latest
  && officialVersion xo.channels.stable
  && rollingVersion xo.channels.rolling
  && lib.all validXoPin (builtins.attrValues xo.channels)
  && builtins.compareVersions xo.channels.latest.version xo.channels.stable.version > 0
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
