{
  description = "mosey — peer-to-peer terminal sharing (Firefly tool)";

  inputs = {
    nix-pins.url = "github:firefly-engineering/nix-pins";
    nixpkgs.follows = "nix-pins/nixpkgs";
    toolbox.url = "github:firefly-engineering/toolbox";
    toolbox.inputs.nix-pins.follows = "nix-pins";
    toolbox.inputs.devenv.follows = "";
  };

  outputs =
    {
      self,
      nixpkgs,
      toolbox,
      ...
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          # Full developer shell. Mirrors shepherd's so contributors who
          # move between repos hit the same baseline (toolbox toolchains
          # + nix tooling + protobuf for the cert/control proto regen).
          default = pkgs.mkShell {
            packages =
              with pkgs;
              [
                # Nix tooling
                nixfmt-tree
                nil
                # protoc + Go plugin for control.proto / cert.proto / auth.proto
                protobuf
                protoc-gen-go
                # Test runner with cleaner output + per-package summaries
                gotestsum
              ]
              ++ (with toolbox.packages.${system}; [
                beadwork
                go-toolchain
                just
                mdbook-toolchain
                vcs-toolchain
              ]);

            shellHook = ''
              echo "mosey dev shell"
            '';
          };
        }
      );

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          # buildGoModule's bundled Go is from nixpkgs (currently 1.25);
          # our go.mod is on 1.26 and Nix builds run sandboxed (no
          # network), so Go's auto-toolchain download can't rescue us.
          # Pin the toolbox's 1.26 build to keep CI and nix build in sync.
          buildGoModule = pkgs.buildGoModule.override {
            go = toolbox.packages.${system}.go-1_26_2;
          };
        in
        {
          default =
            let
              releaseVersion = "v0.0.0-dev";
            in
            buildGoModule {
              pname = "mosey";
              version = releaseVersion;
              src = ./.;
              # Bump when go.sum changes; `nix build` will print the
              # expected value on mismatch.
              vendorHash = null;
              subPackages = [ "cmd/mosey" ];
              ldflags = [
                "-s"
                "-w"
              ];
              # `go test ./...` runs in just/CI; the package build keeps
              # the artifact path quick.
              doCheck = false;
              meta = {
                description = "mosey — peer-to-peer terminal sharing";
                mainProgram = "mosey";
              };
            };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);
    };
}
