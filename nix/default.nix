{ pkgs, buildPythonPackage, pythonVersion, extras, ... }:
buildPythonPackage rec {
  src = pkgs.lib.cleanSource ../.;
  python = pythonVersion;
  version = "2022.7.22";
  inherit extras;

  _ = {};
  providers = {};
  passthru.meta.mach-nix = {
    inherit providers _;
  };
}
