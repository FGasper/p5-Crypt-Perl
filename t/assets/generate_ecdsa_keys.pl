#!/usr/bin/env perl

use strict;
use warnings;
use autodie;

use FindBin ();

use lib "$FindBin::Bin/../lib";
use OpenSSL_Control ();

my $openssl_bin = OpenSSL_Control::openssl_bin();

for my $param_enc ( qw( named_curve explicit ) ) {
    my $dir = "$FindBin::Bin/ecdsa_$param_enc";
    CORE::mkdir( $dir ) or do {
        die "$dir: $!" if !$!{'EEXIST'};
    };

    for my $curve ( OpenSSL_Control::curve_names() ) {
        print "Generating $curve ($param_enc) …$/";

        system(
            $openssl_bin, 'ecparam',
            '-genkey',
            '-noout',
            -name => $curve,
            -out => "$dir/$curve.key",
            -param_enc => $param_enc,
        );
    }
}

print "Done!$/";
