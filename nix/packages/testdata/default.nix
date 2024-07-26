{
  inputs,
  lib,
  system,
  age,
  just,
  stdenv,
  ...
}: let
  age-threshold' = inputs.self.packages.${system}.default.overrideAttrs (_: {
    # since we could be in a situation where the testdata is stale and we need to regenerate it,
    # avoid checking to break out of the loop.
    doCheck = false;
  });
  inherit (inputs.self.packages.${system}) age-plugin-simplepq;
in
  stdenv.mkDerivation {
    name = "age-threshold-testdata";
    src = lib.snowfall.fs.get-file "testdata";

    buildInputs = [age-threshold' age-plugin-simplepq age just];

    buildPhase = "ls; pwd; just generate";

    installPhase = "cp -R . $out";
  }
