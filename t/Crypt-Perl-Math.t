package t::Crypt::Perl::ECDSA::PublicKey;

use strict;
use warnings;

BEGIN {
    if ( $^V ge v5.10.1 ) {
        require autodie;
    }
}

use FindBin;
use lib "$FindBin::Bin/../lib";

use Test::More;
use Test::NoWarnings;
use Test::Deep;
use Test::Exception;

use lib "$FindBin::Bin/lib";

use parent qw(
    Test::Class
);

use Crypt::Perl::RSA::Math ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

sub test_create_random_bit_length : Tests(745) {
    my ($self) = @_;

    for ( 24 .. 768 ) {
        my $num = Crypt::Perl::RSA::Math::create_random_bit_length($_);
        is(
            $num->bit_length(),
            $_,
            "$_-bit random number created correctly: " . $num->as_hex(),
        );
    }

    return;
}

sub test_ceil : Tests(10) {
    my ($self) = @_;

    for ( map { $_ / 10 } 11 .. 20 ) {
        is(
            Crypt::Perl::RSA::Math::ceil($_),
            2,
            "ceil($_)",
        );
    }

    return;
}
