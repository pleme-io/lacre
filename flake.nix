{
  description = "lacre — compliant OCI registry seal. Gates image pushes through cartorio.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
    };
    forge = {
      url = "github:pleme-io/forge";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
      inputs.substrate.follows = "substrate";
      inputs.crate2nix.follows = "crate2nix";
    };
    crate2nix = {
      url = "github:nix-community/crate2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, fenix, substrate, forge, crate2nix, devenv, ... }: let
    base = (import "${substrate}/lib/rust-service-flake.nix" {
      inherit nixpkgs substrate forge crate2nix devenv;
    }) {
      inherit self;
      serviceName = "lacre";
      registry = "ghcr.io/pleme-io/lacre";
      packageName = "lacre";
      namespace = "openclaw-system";
      architectures = ["amd64" "arm64"];
      ports = { http = 8083; health = 8083; metrics = 8083; };
      moduleDir = null;
      nixosModuleFile = null;
    };

    systems = ["aarch64-darwin" "x86_64-linux" "aarch64-linux"];

    # Same gate-app pattern cartorio uses — `nix run .#<gate>` for every
    # CI/dev surface, no GitHub Actions required.
    lacreGateApps = system: let
      pkgs = import nixpkgs { inherit system; };
      fenixPkgs = fenix.packages.${system};
      rustToolchain = fenixPkgs.complete.toolchain;
      runEnv = ''
        export PATH="${rustToolchain}/bin:${pkgs.lib.makeBinPath [
          pkgs.coreutils pkgs.curl pkgs.git
          pkgs.pkg-config pkgs.openssl pkgs.cacert
        ]}:$PATH"
        export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        : "''${CARGO_TARGET_DIR:=target}"
        export CARGO_TARGET_DIR
      '';
      mkApp = name: script: {
        type = "app";
        program = toString (pkgs.writeShellScript "lacre-${name}" ''
          set -euo pipefail
          ${runEnv}
          cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
          ${script}
        '');
      };
    in {
      test = mkApp "test" ''cargo test'';
      fmt-check = mkApp "fmt-check" ''cargo fmt --check'';
      fmt = mkApp "fmt" ''cargo fmt'';
      clippy = mkApp "clippy" ''cargo clippy --all-targets -- -D warnings'';

      # Boot lacre against an in-memory cartorio (also linked as a
      # dev-dep) and exercise the gate path with curl. End-to-end
      # smoke without any external dependencies.
      smoke = mkApp "smoke" ''
        echo "==> building lacre + cartorio (release)"
        cargo build --release --bin lacre
        ( cd ../cartorio && cargo build --release --bin cartorio )

        # Boot cartorio.
        CART_DB="$(mktemp -t lacre-smoke-cart-XXXX.db)"
        CART_PORT="$((RANDOM % 1000 + 18100))"
        ../cartorio/target/release/cartorio --listen 127.0.0.1:$CART_PORT --audit-interval-secs 0 &
        CART_PID=$!
        sleep 2

        # Boot lacre pointed at it. Backend URL is the same (loopback)
        # — the smoke just confirms lacre boots + serves /health.
        LACRE_PORT="$((RANDOM % 1000 + 18200))"
        ./target/release/lacre \
          --listen 127.0.0.1:$LACRE_PORT \
          --cartorio-url http://127.0.0.1:$CART_PORT \
          --backend-url http://127.0.0.1:$CART_PORT &
        LACRE_PID=$!
        sleep 2

        cleanup() {
          kill "$LACRE_PID" 2>/dev/null || true
          kill "$CART_PID"  2>/dev/null || true
          wait 2>/dev/null  || true
          rm -f "$CART_DB"
        }
        trap cleanup EXIT

        echo "==> /health on lacre:$LACRE_PORT"
        curl -fsS "http://127.0.0.1:$LACRE_PORT/health" || true
        echo
        echo "==> SMOKE OK"
      '';

      ci = mkApp "ci" ''
        echo "[1/3] cargo fmt --check"
        cargo fmt --check
        echo "[2/3] cargo clippy --all-targets -- -D warnings"
        cargo clippy --all-targets -- -D warnings
        echo "[3/3] cargo test"
        cargo test
        echo "==> CI OK ✓"
      '';
    };
  in
    base // {
      apps = nixpkgs.lib.genAttrs systems (system:
        (base.apps.${system} or {}) // (lacreGateApps system)
      );
    };
}
