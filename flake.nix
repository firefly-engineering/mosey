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

          # On-chain (wallet auth) SBF toolchain. nixpkgs' solana-cli
          # ships the SBF SDK *scaffolding* but not the platform-tools
          # toolchain (sbpf rustc/LLVM), and its default tools predate the
          # program's edition2024 deps. Pin platform-tools as a
          # fixed-output derivation and assemble a complete, offline SBF
          # SDK so `just anchor-build` never downloads. Hashes are
          # per-system; fill the rest when this moves to the toolbox.
          sbfToolsVersion = "v1.54";
          sbfAsset = {
            x86_64-linux = "platform-tools-linux-x86_64.tar.bz2";
            aarch64-linux = "platform-tools-linux-aarch64.tar.bz2";
            x86_64-darwin = "platform-tools-osx-x86_64.tar.bz2";
            aarch64-darwin = "platform-tools-osx-aarch64.tar.bz2";
          };
          sbfHash = {
            aarch64-darwin = "sha256-HIs69ehhThxFk5OpXFsZv7zI7ROCKhy1OfrmhHH5v7s=";
            # TODO(toolbox): x86_64-darwin / aarch64-linux / x86_64-linux.
          };
          hasPinnedSbf = builtins.hasAttr system sbfHash;
          platformTools = pkgs.fetchurl {
            url = "https://github.com/anza-xyz/platform-tools/releases/download/${sbfToolsVersion}/${sbfAsset.${system}}";
            hash = sbfHash.${system} or "";
          };
          # A complete SBF SDK: nixpkgs scaffolding + pinned platform-tools
          # mounted where cargo-build-sbf --skip-tools-install expects them.
          sbfSdk = pkgs.runCommand "mosey-sbf-sdk-${sbfToolsVersion}" { } ''
            cp -R ${pkgs.solana-cli}/bin/platform-tools-sdk $out
            chmod -R u+w $out
            mkdir -p $out/sbf/dependencies/platform-tools
            tar -xjf ${platformTools} -C $out/sbf/dependencies/platform-tools
          '';
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
                # On-chain (wallet auth, Track B): Solana CLI + Anchor.
                # `just anchor-build` builds the program against the pinned
                # SBF SDK below (MOSEY_SBF_SDK) — no download. Heavyweight
                # (~300 MiB) — a candidate to split into a `.#onchain`
                # shell or the toolbox later.
                solana-cli
                anchor
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
            ''
            + pkgs.lib.optionalString hasPinnedSbf ''
              export MOSEY_SBF_SDK="${sbfSdk}/sbf"
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
