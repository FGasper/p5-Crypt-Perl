package t::Crypt::Sign_RS256;

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

use parent qw( Test::Class );

use Crypt::Perl::BigInt ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

use constant _HEX => '028cff19d53ced26bdd41ca5d926751503e3f9561f6e5cb8afe189afd881e1086d';

sub _num {
    return Crypt::Perl::BigInt->from_hex(_HEX());
}

sub bytes_conversion : Tests(2) {
    is(
        _num()->as_bytes(),
        pack('H*', _HEX()),
        'as_bytes()',
    );

    is(
        Crypt::Perl::BigInt->from_bytes( pack('H*', _HEX()) )->as_hex(),
        _num()->as_hex(),
        'from_bytes()',
    );

    return;
}

sub test_bit_length : Tests(2) {
    my $num = _num();

    is( $num->bit_length(), 258, 'bit_length()' );
    is( $num->bit_length(), 258, 'bit_length(), repeated' );

    return;
}

1;
