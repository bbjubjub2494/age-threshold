{
  inputs,
  system,
  clippy,
  ...
}:
inputs.self.packages.${system}.default.overrideAttrs (prev: {
  name = "${prev.name}-cargo-clippy";

  nativeCheckInputs = (prev.nativeCheckInputs or []) ++ [clippy];

  dontCargoBuild = true;
  checkPhase = "cargo clippy";
  installPhase = "touch $out";
})
