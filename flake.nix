{
  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; }; in rec {
        defaultPackage = pkgs.stdenv.mkDerivation {
          pname = "cmls";
          version = "0.0.1";
          src = ./.;

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs; [
            jansson
            openssl_3_2
          ];

          buildPhase = "make -j $NIX_BUILD_CORES";

          doCheck = true;
          checkPhase = "make test";
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
