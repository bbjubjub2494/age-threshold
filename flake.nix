{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    crate2nix.url = "github:nix-community/crate2nix";

    snowfall-lib.url = "github:snowfallorg/lib";
    snowfall-lib.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = inputs:
    inputs.snowfall-lib.mkFlake {
      inherit inputs;
      src = ./.;
      snowfall.root = ./nix;
      outputs-builder = channels: {
        formatter = channels.nixpkgs.alejandra;
        cargoNix = inputs.crate2nix.tools.${channels.nixpkgs.system}.appliedCargoNix {
            name = "age-threshold";
            src = ./.;
          };
      };
    };
}
