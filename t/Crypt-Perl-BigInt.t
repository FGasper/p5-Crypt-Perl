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

sub test_bit_length : Tests(2) {
    my $num = Crypt::Perl::BigInt->new('295358701570351778990985646722256307679121357691957565958901674843561986689133');

    is( $num->bit_length(), 258, 'bit_length()' );
    is( $num->bit_length(), 258, 'bit_length(), repeated' );

    return;
}
