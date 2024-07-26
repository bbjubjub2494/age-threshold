{
  inputs,
  system,
  age,
  just,
  mkShell,
  ...
}:
mkShell {
  packages = [inputs.self.packages.${system}.default age just];
}
