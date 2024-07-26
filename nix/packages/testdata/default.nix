{
  inputs,
  lib,
  system,
  age,
  just,
  stdenv,
  ...
}:
stdenv.mkDerivation {
  name = "age-threshold-testdata";
  src = lib.snowfall.fs.get-file "testdata";

  buildInputs = [inputs.self.packages.${system}.default age just];

  buildPhase = "ls; pwd; just generate";

  installPhase = "cp -R . $out";
}
