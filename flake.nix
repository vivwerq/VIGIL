{
  description = "VIGIL — Air-Gapped Predictive AI NOC Copilot";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    let
      systemOutputs = flake-utils.lib.eachDefaultSystem (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs { inherit system overlays; };

          # Pinned Rust toolchain matching rust-toolchain.toml
          rustToolchain = pkgs.rust-bin.stable."1.85.0".default.override {
            extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
            targets = [ "x86_64-unknown-linux-gnu" ];
          };
        in
        {
          devShells.default = pkgs.mkShell {
            name = "vigil-dev";

            buildInputs = with pkgs; [
              # Rust toolchain
              rustToolchain
              pkg-config
              openssl

              # Build tools
              mold        # Fast linker
              cmake
              gnumake

              # Development tools
              cargo-deny    # Dependency audit
              cargo-audit   # Vulnerability scanning
              cargo-watch   # Auto-rebuild on changes
              cargo-nextest # Better test runner

              # Debugging & profiling
              gdb
              valgrind
              linuxPackages.perf
            ];

            shellHook = ''
              echo "╔══════════════════════════════════════════╗"
              echo "║  VIGIL Development Environment Active    ║"
              echo "║  Rust $(rustc --version | cut -d' ' -f2) | Air-Gapped NOC Copilot  ║"
              echo "╚══════════════════════════════════════════╝"
              export RUST_LOG="vigil=debug,warn"
              export RUST_BACKTRACE=1
            '';
          };

          packages.default = pkgs.rustPlatform.buildRustPackage {
            pname = "vigil";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = with pkgs; [ pkg-config cmake ];
            buildInputs = with pkgs; [ openssl ];

            # Hardened build flags
            RUSTFLAGS = "-C force-frame-pointers=yes";
          };
        });
    in
      systemOutputs // {
        nixosModules.default = { config, lib, pkgs, ... }:
          let
            cfg = config.services.vigil;
          in {
            options.services.vigil = {
              enable = lib.mkEnableOption "VIGIL Anomaly Detection and AI NOC Copilot daemon";
              package = lib.mkOption {
                type = lib.types.package;
                default = self.packages.${pkgs.system}.default;
              };
              bindAddress = lib.mkOption {
                type = lib.types.str;
                default = "127.0.0.1:3000";
              };
              configPath = lib.mkOption {
                type = lib.types.path;
                default = "/etc/vigil/vigil.toml";
              };
            };
            config = lib.mkIf cfg.enable {
              systemd.services.vigil = {
                description = "VIGIL Ground-station Anomaly Detection Daemon";
                after = [ "network.target" ];
                wantedBy = [ "multi-user.target" ];
                serviceConfig = {
                  ExecStart = "${cfg.package}/bin/vigil-daemon --mode production --bind-address ${cfg.bindAddress} --config ${cfg.configPath}";
                  User = "vigil-daemon";
                  Group = "vigil-daemon";
                  Restart = "on-failure";
                  ProtectSystem = "strict";
                  ProtectHome = true;
                  PrivateTmp = true;
                  StateDirectory = "vigil";
                  ConfigurationDirectory = "vigil";
                };
              };
              users.users.vigil-daemon = {
                isSystemUser = true;
                group = "vigil-daemon";
                description = "VIGIL system daemon user";
              };
              users.groups.vigil-daemon = {};
            };
          };
      };
}
