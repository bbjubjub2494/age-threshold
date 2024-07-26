{
  lib,
  rustPlatform,
  ...
}:
rustPlatform.buildRustPackage {
  name = "age-threshold";
  src = lib.snowfall.fs.get-file "";

  cargoHash = "sha256-5Z0+pd65fwAssRyw1MqBYBIX0tjmU9/SGPSxLyjQX0g=";
}
