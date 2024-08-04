{
  fetchFromGitHub,
  inputs,
  system,
}:

(inputs.crate2nix.tools.${system}.appliedCargoNix {
  name = "age-plugin-simplepq";

  src = fetchFromGitHub {
    owner = "thibmeu";
    repo = "age-plugin-simplepq";
    rev = "1983deafb7736d3a23ddb9e971f52c3392128729";
    hash = "sha256-qk8VxYvNb13/FEt2GYfh3grpthyESTAsv7Ia8Znc2o8=";
  };
}).workspaceMembers.age-plugin-simplepq.build
