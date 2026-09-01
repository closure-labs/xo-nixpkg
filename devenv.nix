{ pkgs, ... }:

let
  developmentEnvironment = import ./nix/development-environment.nix { inherit pkgs; };
in
{
  # Devenv resolves the public URL and signing key for this cache name and
  # applies them as extra-substituters and extra-trusted-public-keys.
  cachix.pull = [ "xen-orchestra-ce" ];

  inherit (developmentEnvironment) packages;
  env = developmentEnvironment.env // {
    # Pin the same trust root for Nix commands run from inside the shell.
    NIX_CONFIG = ''
      extra-substituters = https://xen-orchestra-ce.cachix.org
      extra-trusted-public-keys = xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E=
    '';
  };

  enterTest = ''
    command -v nixfmt >/dev/null
    command -v node >/dev/null
    command -v yarn >/dev/null
    [[ $NIX_CONFIG == *https://xen-orchestra-ce.cachix.org* ]]
    [[ $NIX_CONFIG == *xen-orchestra-ce.cachix.org-1:WAOajkFLXWTaFiwMbLidlGa5kWB7Icu29eJnYbeMG7E=* ]]
  '';
}
