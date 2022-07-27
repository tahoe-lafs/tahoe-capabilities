{ pkgs

# The name of the Python derivation in nixpkgs for which to build the package.
, pythonVersion

# The Tahoe-Capabilities package itself, including its test requirements.
, tahoe-capabilities

# The mach-nix builder to use to build the test environment.
, mkPython
}:
let
  # Make the Python environment in which we can run the tests.
  python-env = mkPython {
    # Use the specified Python version - which must match the version of the
    # Tahoe-Capabilities package given.
    python = pythonVersion;

    packagesExtra = [ tahoe-capabilities ];
  };
in
# Make a derivation that runs the unit test suite.
pkgs.runCommand "tahoe-capabilities-tests" { } ''
  ${python-env}/bin/python -m twisted.trial tahoe_capabilities

  # It's not cool to put the whole _trial_temp into $out because it can have
  # weird files in it we don't want in the store.  Plus, even all of the less
  # weird files are mostly just trash that's not meaningful if the test suite
  # passes (which is the only way we get $out anyway).
  #
  # The build log itself is typically available from `nix log` so we don't
  # need to record that either.
  echo "passed" >$out
''
