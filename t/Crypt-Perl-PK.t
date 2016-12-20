package t::Crypt::Perl::PK;

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

use File::Temp;

use lib "$FindBin::Bin/lib";

use parent qw(
    Test::Class
);

use Crypt::Perl::PK ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

sub test__parse_jwk__rsa : Tests(2) {

    my ($pr_jwk) = {
        kty => 'RSA',
        n => "0ZnvJBJiEp9hO1BOwKyA6dvVoS8ij0IlMOAp2oj2ZkiEdyaGO4aL5Lq2LIQKvFpLzRmQlmApFlnOlLbhxZCuF53iGC0IU0Z02jBfEdWiewL4L2dSCvw14-Z-oVWBJfwN",
        e => "AQAB",
        d => "NILvUcc1QNsjPfvxrv3I0k4cKGSpsOBudt9CPRjhOmDipwNEz_b2Z1iLuX1fPy8TqHpTv4ECDOIs2ArAvZabrrPmjjPo8rzbzlyTLoAaqBNVGpzQuFnOKONkil9gY7A1",
        p => "63Omrbj0-jqnCFYA4He0Tn6OzZyFPL-tmcWcCD9U4fSAZXsEFZhcJWPrtJPXFpdn",
        q => "4-S-pP0u32ty6kshqFDSKYxCrzuY6_7Pbw-6pd-w1hElmxY9sZ7PdVxeGpTveSxr",
        dp => "exO_Yzw1wr_6JF9gofWw6P87Arv44eKIisNDZwRECMFYhLOjVO6J7Hmo8oH9gy-t",
        dq => "3pOiv3GoPf2rlrkaflGxcXLUDmGe0Z9k6YvrN-ZpyCmnGPl39-qrpGw6XKvp1-dR",
        qi => "w0uFy3hHFZL94Xk0JK6VApoNY6czBmIBhCbHSIKKfpKoDVQzfqMYN8Q6jBTPH-ln",
    };

    isa_ok(
        Crypt::Perl::PK::parse_jwk($pr_jwk),
        'Crypt::Perl::RSA::PrivateKey',
        'parse_jwk($rsa_private_jwk)',
    );

    my ($pub_jwk) = {
        kty => 'RSA',
        n => "0ZnvJBJiEp9hO1BOwKyA6dvVoS8ij0IlMOAp2oj2ZkiEdyaGO4aL5Lq2LIQKvFpLzRmQlmApFlnOlLbhxZCuF53iGC0IU0Z02jBfEdWiewL4L2dSCvw14-Z-oVWBJfwN",
        e => "AQAB",
    };

    isa_ok(
        Crypt::Perl::PK::parse_jwk($pub_jwk),
        'Crypt::Perl::RSA::PublicKey',
        'parse_jwk($rsa_public_jwk)',
    );

    return;
}

sub test__parse_jwk__ecdsa : Tests(2) {
    my ($pr_jwk) = {
        kty => 'EC',
        crv => 'P-384',
        x => '7r2u_ZkCnSjowORDMgnqWvI1A9HQ6CH06LIAaftFO2iYYazSICi-HoH_M2tBn4fR',
        y => 'ouVhCnZ-g4E8aVqgJcqmIdiGZIN8qlqWG9K8wvFKWvUbSI561j_WXuKH3cBp0ewq',
        d => '5ITbOa5Bw3lhq5doenNkZ-JcJVT0e4sWQpdtfo-5et9-Bqx8qQv8T9T1wS-jCZB2',
    };

    isa_ok(
        Crypt::Perl::PK::parse_jwk($pr_jwk),
        'Crypt::Perl::ECDSA::PrivateKey',
        'parse_jwk($ecc_private_jwk)',
    );

    my ($pub_jwk) = {
        kty => 'EC',
        crv => 'P-384',
        x => '7r2u_ZkCnSjowORDMgnqWvI1A9HQ6CH06LIAaftFO2iYYazSICi-HoH_M2tBn4fR',
        y => 'ouVhCnZ-g4E8aVqgJcqmIdiGZIN8qlqWG9K8wvFKWvUbSI561j_WXuKH3cBp0ewq',
    };

    isa_ok(
        Crypt::Perl::PK::parse_jwk($pub_jwk),
        'Crypt::Perl::ECDSA::PublicKey',
        'parse_jwk($ecc_public_jwk)',
    );

    return;
}
