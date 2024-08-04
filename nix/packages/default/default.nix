{
  lib,
  rustPlatform,
  inputs,
  system,
  ...
}:
inputs.self.cargoNix.${system}.workspaceMembers.three.build.override {
  runTests = true;
}
