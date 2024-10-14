{ pkgs ? import <nixpkgs> { } }:

let
    # dont forget to remove it from nix store when your done, cause its not automatic and I dont
    # know how to make it automatic, commad: `locate softflowd`
    softflowd = pkgs.stdenv.mkDerivation {
        name = "softflowd";
        src = builtins.fetchGit {
            url = "https://github.com/irino/softflowd";
            ref = "master";
            rev = "433fbb7102616c671d523d4e41ae5315cd70d442";
        };
        buildInputs = [ 
            pkgs.autoconf
            pkgs.automake
            pkgs.libtool
            pkgs.gcc
            pkgs.libpcap
        ];
        buildPhase = ''
            autoreconf -if
            ./configure
            make
        '';
        installPhase = ''
            mkdir -p $out/bin
            cp softflowd $out/bin/
            cp softflowctl $out/bin/
        '';
    };
in

pkgs.mkShell 
{
	name = "C networking";
	buildInputs = with pkgs;
	[
		libnet
		libpcap
        nfdump      # netflow collector
        tcpdump     # packet sniffer
        softflowd
        ghostscript # to make man pages for softflow
	];

	hardeningDisable = ["all"];
}
