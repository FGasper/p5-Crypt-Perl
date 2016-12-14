package t::Crypt::Perl::ECDSA::Generate;

use strict;
use warnings;

BEGIN {
    if ( $^V ge v5.10.1 ) {
        require autodie;
    }
}

use Try::Tiny;

use FindBin;

use lib "$FindBin::Bin/lib";
use OpenSSL_Control ();

use Test::More;
use Test::NoWarnings;
use Test::Deep;
use Test::Exception;

use Crypt::Format ();
use Digest::SHA ();
use File::Slurp ();
use File::Temp ();

use lib "$FindBin::Bin/lib";
use parent qw(
    NeedsOpenSSL
    Test::Class
);

use OpenSSL_Control ();

use lib "$FindBin::Bin/../lib";

use Crypt::Perl::ECDSA::Generate ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

sub test_generate : Tests(9) {
    my ($self) = @_;

    my $msg = rand;

    #Use SHA1 since it’s the smallest digest that the latest OpenSSL accepts.
    my $dgst = Digest::SHA::sha1($msg);
    my $digest_alg = 'sha1';

    for my $curve ( qw( prime256v1 secp384r1 secp521r1 ) ) {
        my $key_obj = Crypt::Perl::ECDSA::Generate::by_name($curve);

        isa_ok(
            $key_obj,
            'Crypt::Perl::ECDSA::PrivateKey',
            'return of by_name()',
        );

        my $sig = $key_obj->sign($dgst);

        ok( $key_obj->verify( $dgst, $sig ), 'verify() on self' );

        ok(
            OpenSSL_Control::verify_private(
                Crypt::Format::der2pem($key_obj->to_der_with_curve_name(), 'EC PRIVATE KEY'),
                $msg,
                $digest_alg,
                $sig,
            ),
            "$curve: OpenSSL verifies",
        );
    }

    return;
}

1;
