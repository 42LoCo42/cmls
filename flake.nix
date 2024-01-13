{
  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; }; in rec {
        defaultPackage = pkgs.stdenv.mkDerivation {
          pname = "cmls";
          version = "0.0.1";
          src = ./.;

          nativeBuildInputs = with pkgs; [
            jq
            pkg-config
          ];

          doCheck = true;
        };

        devShell = pkgs.mkShell {
          inputsFrom = [ defaultPackage ];
          packages = with pkgs; [
            bear
            clang-tools
          ];
        };
      });
}
