let pkgs = (import <nixpkgs> {}); in let unstable-pkgs = (import <nixpkgs-unstable> {});

in pkgs.mkShell rec {
    name = "interview";
    shellHook = ''
        source .bashrc
        export MALLOC_TRIM_THRESHOLD_=131072
    '';
    buildInputs = (with pkgs; [
        bashInteractive
        (pkgs.python3.buildEnv.override {
            ignoreCollisions = true;
            extraLibs = [
                # package list: https://search.nixos.org/packages
                # be parsimonious with 3rd party dependencies; better to show off your own code than someone else's
                pkgs.python3.pkgs.lxml
                pkgs.python3.pkgs.charset-normalizer
                pkgs.python3.pkgs.h2
                pkgs.python3.pkgs.aiodns
                unstable-pkgs.python3.pkgs.onecache
                unstable-pkgs.python3.pkgs.aiosonic
            ];
        })
    ]);
}
