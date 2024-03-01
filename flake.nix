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

        packages.plugin = pkgs.rustPlatform.buildRustPackage {
          name = "age-plugin-threshold";
          src = ./plugin;

          cargoHash = "sha256-JcanrL0o1V5OkGKSpOejyDaIKiJyHnLhUkNje35L9CE=";
        };

        checks.e2e = pkgs.rustPlatform.buildRustPackage {
          name = "age-plugin-threshold-e2e_tests";
          src = ./e2e_tests;

          cargoHash = "sha256-Lh15x4l/c7lDrHSLJ16XS6qFnml9WtbuPmVNt7YSHac=";

          nativeCheckInputs = [packages.plugin pkgs.age];
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
