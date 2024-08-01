{
  lib,
  rustPlatform,
  inputs,
  system,
  ...
}:
rustPlatform.buildRustPackage {
  name = "age-threshold";
  src = lib.snowfall.fs.get-file "";

  nativeBuildInputs = [inputs.self.packages.${system}.age-plugin-simplepq];

  cargoHash = "sha256-5Z0+pd65fwAssRyw1MqBYBIX0tjmU9/SGPSxLyjQX0g=";
}
