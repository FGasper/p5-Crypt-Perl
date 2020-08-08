#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Test::Deep;
use Test::FailWarnings;

use Crypt::Perl::BigInt;
use Crypt::Perl::ECDSA::EC::Curve;
use Crypt::Perl::ECDSA::EC::DB;

use Crypt::Perl::ECDSA::EC::Point;

my $curve_hr = Crypt::Perl::ECDSA::EC::DB::get_curve_data_by_name('prime256v1');

my $curve_obj = Crypt::Perl::ECDSA::EC::Curve->new( @{$curve_hr}{ qw( p a b ) } );

my @tests = (
    [
        {
            x => '0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
            y => '0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
        },
        '0xf691d849684571f1f682c82e3ac5dfc76e5659745beae358af518f4f1bc66f64',
        {
            x => '0x2ebd78a0c333c2003b67d101380bc5260166ba2e8db634140fbb7a395f462571',
            y => '0x392e3196293c847c29080ef290bb391d640220ce623fe737d65a43055532b3ec',
        },
    ],
);

my $count = 0;

for my $t_ar (@tests) {
    $count++;

    my ($point_hr, $k, $expect_hr) = @$t_ar;

    my $x_int = Crypt::Perl::BigInt->from_hex($point_hr->{'x'});
    my $y_int = Crypt::Perl::BigInt->from_hex($point_hr->{'y'});

    my $x_fe = $curve_obj->from_bigint($x_int);
    my $y_fe = $curve_obj->from_bigint($y_int);

    #$expect_hr->{'z'} = Crypt::Perl::BigInt->from_hex($expect_hr->{'z'});
    my $k_int = Crypt::Perl::BigInt->from_hex($k);

#diag explain $point_hr;

    my $point = Crypt::Perl::ECDSA::EC::Point->new(
        $curve_obj,
        $x_fe, $y_fe,
    );

    my $got = $point->multiply($k_int);

diag explain [ x =>  ];

    for my $axis ( 'x', 'y' ) {
        my $getter = "get_$axis";

        is(
            $got->$getter()->to_bigint()->as_hex(),
            $expect_hr->{$axis},
            "$count: $axis",
        );
    }

use Math::EllipticCurve::Prime;
use Math::EllipticCurve::Prime::Point;
my $mep_point = Math::EllipticCurve::Prime::Point->new(
curve => 'P256',
x => $x_int,
y => $y_int,
);
diag explain [ $mep_point->x()->as_hex(), $mep_point->y()->as_hex() ];
my $mult = $mep_point->multiply($k_int);
diag explain [ $mult->x()->as_hex(), $mult->y()->as_hex() ];
}

done_testing;

1;
