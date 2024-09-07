{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    hercules-ci-effects.url = "github:hercules-ci/hercules-ci-effects";
  };

  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} {
      imports = [
        inputs.hercules-ci-effects.flakeModule
      ];
      systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
      # NOTE: I do not have runners for darwin
      herculesCI.ciSystems = ["x86_64-linux" "aarch64-linux"];

      hercules-ci.flake-update.enable = true;
      hercules-ci.flake-update.when.dayOfWeek = "Sat";

      perSystem = {pkgs, ...}: let
        age-plugin-simplepq = pkgs.rustPlatform.buildRustPackage {
          pname = "age-plugin-simplepq";
          version = "0.1.2";

          src = pkgs.fetchFromGitHub {
            owner = "thibmeu";
            repo = "age-plugin-simplepq";
            rev = "1983deafb7736d3a23ddb9e971f52c3392128729";
            hash = "sha256-qk8VxYvNb13/FEt2GYfh3grpthyESTAsv7Ia8Znc2o8=";
          };

          cargoHash = "sha256-RnLizkhW33d71fsdYg8FnTRnFpfO7lbl1QExhRTDlRM=";

          meta = {
            description = "Simple Post Quantum plugin for age";
            homepage = "https://github.com/thibmeu/age-plugin-simplepq";
            license = pkgs.lib.licenses.mit;
            mainProgram = "age-plugin-simplepq";
          };
        };

        age-threshold = pkgs.rustPlatform.buildRustPackage {
          name = "age-threshold";
          src = ./.;

          checkInputs = [age-plugin-simplepq];

          cargoHash = "sha256-5Z0+pd65fwAssRyw1MqBYBIX0tjmU9/SGPSxLyjQX0g=";
        };

        testdata = let
          age-threshold' = age-threshold.overrideAttrs (_: {
            # since we could be in a situation where the testdata is stale and we need to regenerate it,
            # avoid checking to break out of the loop.
            doCheck = false;
          });
        in
          pkgs.stdenv.mkDerivation {
            name = "age-threshold-testdata";
            src = ./testdata;

            buildInputs = [age-threshold' age-plugin-simplepq pkgs.age pkgs.just];

            buildPhase = "just";

            installPhase = "cp -R . $out";
          };
      in {
        packages = {
          inherit age-plugin-simplepq age-threshold testdata;
          default = age-threshold;
        };

        checks.clippy = age-threshold.overrideAttrs (prev: {
          name = "${prev.name}-cargo-clippy";

          nativeCheckInputs = (prev.nativeCheckInputs or []) ++ [pkgs.clippy];

          dontCargoBuild = true;
          checkPhase = "cargo clippy";
          installPhase = "touch $out";
        });

        checks.fmt = age-threshold.overrideAttrs (prev: {
          name = "${prev.name}-cargo-fmt";

          nativeCheckInputs = (prev.nativeCheckInputs or []) ++ [pkgs.rustfmt];

          dontCargoBuild = true;
          checkPhase = "cargo fmt --check";
          installPhase = "touch $out";
        });

        checks.generate-testdata = age-threshold.overrideAttrs (prev: {
          name = "${prev.name}-generate-testdata";

          postUnpackPhase = ''
            rm -rf testdata
            cp -R ${testdata} testdata
          '';
          # run all rust tests with the new testdata
          installPhase = "touch $out";
        });

        formatter = pkgs.alejandra;
      };
    };
}
