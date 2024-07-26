{
  inputs,
  system,
  rustfmt,
  ...
}:
inputs.self.packages.${system}.default.overrideAttrs (prev: {
  name = "${prev.name}-cargo-fmt";

  nativeCheckInputs = (prev.nativeCheckInputs or []) ++ [rustfmt];

  dontCargoBuild = true;
  checkPhase = "cargo fmt --check";
  installPhase = "touch $out";
})
