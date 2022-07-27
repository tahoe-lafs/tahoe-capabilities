{ pkgs, buildPythonPackage, pythonVersion, extras, ... }:
buildPythonPackage rec {
  src = pkgs.lib.cleanSource ../.;
  python = pythonVersion;
  version = "2022.7.26";
  inherit extras;
  providers = {};
  _ = {};
  passthru.meta.mach-nix = {
    inherit providers _;
  };
}
