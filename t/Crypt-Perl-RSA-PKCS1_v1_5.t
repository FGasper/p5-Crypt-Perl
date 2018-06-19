#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::Exception;

use Crypt::Perl::RSA::PKCS1_v1_5 ();

my $sha384_str = '00.01.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.ff.00.30.41.30.0d.06.09.60.86.48.01.65.03.04.02.02.05.00.04.30.26.87.56.ad.03.09.4f.ef.7c.26.ef.15.8f.f9.e1.f8.90.23.b3.4a.71.1a.d7.fe.1d.ae.71.23.f9.40.a2.89.e8.37.4a.80.4f.b6.40.c2.e4.bb.5d.26.c7.8a.69.f8';

$sha384_str =~ tr<.><>d;

my $binary = pack 'H*', $sha384_str;

my $decoded;

lives_ok(
    sub {
        $decoded = Crypt::Perl::RSA::PKCS1_v1_5::decode($binary, 'sha384');
    },
    'decode() succeeds (sha384)',
);

is(
    sprintf('%v.02x', $decoded),
    '26.87.56.ad.03.09.4f.ef.7c.26.ef.15.8f.f9.e1.f8.90.23.b3.4a.71.1a.d7.fe.1d.ae.71.23.f9.40.a2.89.e8.37.4a.80.4f.b6.40.c2.e4.bb.5d.26.c7.8a.69.f8',
    'decoded sha384 payload',
);

done_testing();
