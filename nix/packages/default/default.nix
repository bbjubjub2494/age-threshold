{
  lib,
  rustPlatform,
  ...
}:
rustPlatform.buildRustPackage {
  name = "age-threshold";
  src = lib.snowfall.fs.get-file "";

  cargoHash = "sha256-l5Kc0UzRkum7kS45lTwKj7MzQ7EBGxFTGIlFM8ytqd4=";
}
