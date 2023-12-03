# flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
  };

  outputs = {
    self,
    nixpkgs,
  }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
    };
  in 
  with pkgs;
  {
    devShells.${system}.default = mkShell {
      packages = [
        bpftrace
        rustup
        bpf-linker
        cargo-generate
      ];
    };
  };
}
