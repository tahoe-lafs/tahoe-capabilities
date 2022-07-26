{ pkgs, buildPythonPackage, pythonVersion, extras, ... }:
buildPythonPackage rec {
  src = pkgs.lib.cleanSource ../.;
  python = pythonVersion;
  version = "2022.7.26";
  inherit extras;

  _ = {};
  providers = {
    default = "nixpkgs,wheel,sdist";
  };
  passthru.meta.mach-nix = {
    inherit providers _;
  };
}
