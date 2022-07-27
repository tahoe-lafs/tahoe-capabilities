{ pkgs, buildPythonPackage, pythonVersion, extras, ... }:
buildPythonPackage rec {
  src = pkgs.lib.cleanSource ../.;
  python = pythonVersion;
  inherit extras;
  providers = {};
  _ = {};
  passthru.meta.mach-nix = {
    inherit providers _;
  };
}
