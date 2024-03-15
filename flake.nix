{
  description = "Description for the project";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} {
      imports = [
        # To import a flake module
        # 1. Add foo to inputs
        # 2. Add foo as a parameter to the outputs function
        # 3. Add here: foo.flakeModule
      ];
      systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin"];
      perSystem = {
        config,
        self',
        inputs',
        pkgs,
        system,
        ...
      }: rec {
        # Per-system attributes can be defined here. The self' and inputs'
        # module parameters provide easy access to attributes of the same
        # system.

        packages.age-threshold = pkgs.rustPlatform.buildRustPackage {
          name = "age-threshold";
          src = ./age-threshold;

          cargoHash = "sha256-vsMElmhvotaArZdh/9WBuxOA5pmw9Gp05u13ONLWhz4=";
        };

        packages.three = pkgs.rustPlatform.buildRustPackage {
          name = "age-threshold";
          srcs = [./age-threshold ./three];
          sourceRoot = "three";

          cargoHash = "sha256-KDARnp/rg0uIP9MP6MRi5jqm/q6YWb9kKNbmge8PjQ0=";
        };

        packages.default = packages.three;

        checks.integration = pkgs.rustPlatform.buildRustPackage {
          name = "age-threshold-integration";
          src = ./integration;

          cargoHash = "sha256-0DjfmESVAiuP+lyS9Dh4QAZE5mHJ9AF0oxrzV/U3tAk=";

          nativeCheckInputs = [packages.three pkgs.age];
        };

        checks.rust-format = pkgs.stdenv.mkDerivation {
          name = "age-threshold-rust-format";
          src = ./.;

          nativeCheckInputs = [pkgs.cargo pkgs.rustfmt];

          doCheck = true;
          checkPhase = ''
            for p in age-threshold integration three; do
              cargo -Z unstable-options -C $p fmt --check
            done
          '';

          installPhase = "touch $out";
        };

        formatter = pkgs.alejandra;
      };
      flake = {
        # The usual flake attributes can be defined here, including system-
        # agnostic ones like nixosModule and system-enumerating ones, although
        # those are more easily expressed in perSystem.
      };
    };
}
