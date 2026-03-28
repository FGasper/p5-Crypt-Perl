#!/usr/bin/env perl

use strict;
use warnings;
use autodie;

use FindBin ();

use Crypt::PK::RSA ();
use Data::Dumper ();
use MIME::Base64 ();

my @rs256_tests = map {
    my $msg = rand;

    my $use_exp_3 = $msg > 0.5;
    my $size = int($_ / 8);
    my $pk = Crypt::PK::RSA->new();
    my $orsa = $pk->generate_key($size, ($use_exp_3 ? 0x3 : ()));
    [ "$_-bit key" . ($use_exp_3 ? ', exp = 3' : q<>), $orsa->export_key_pem('private'), $msg, MIME::Base64::encode($orsa->sign_message($msg, 'SHA256', 'v1.5')) ];
} (510 .. 768);

open my $rs256_wfh, '>', "$FindBin::Bin/RS256.dump";

{
    local $Data::Dumper::Terse = 1;
    print {$rs256_wfh} Data::Dumper::Dumper(\@rs256_tests) or die $!;
}

close $rs256_wfh;
