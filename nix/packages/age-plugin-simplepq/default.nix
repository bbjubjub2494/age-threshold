{
  lib,
  rustPlatform,
  fetchFromGitHub,
}:
rustPlatform.buildRustPackage rec {
  pname = "age-plugin-simplepq";
  version = "v0.1.2";

  src = fetchFromGitHub {
    owner = "thibmeu";
    repo = "age-plugin-simplepq";
    rev = "1983deafb7736d3a23ddb9e971f52c3392128729";
    hash = "sha256-qk8VxYvNb13/FEt2GYfh3grpthyESTAsv7Ia8Znc2o8=";
  };

  cargoHash = "sha256-qYWylvvI/gnCiy6jsvc//GvLNR6s7mnQIGWFt25FFi8=";

  meta = with lib; {
    description = "Simple Post Quantum plugin for age";
    homepage = "https://github.com/thibmeu/age-plugin-simplepq";
    license = licenses.mit;
    maintainers = with maintainers; [];
    mainProgram = "age-plugin-simplepq";
  };
}
