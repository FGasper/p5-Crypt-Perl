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

use Crypt::Format ();
use Digest::SHA ();
use File::Slurp ();
use File::Temp ();
use MIME::Base64 ();

use lib "$FindBin::Bin/lib";

use parent qw(
    NeedsOpenSSL
    Test::Class
);

use Crypt::Perl::ECDSA::Parse ();
use Crypt::Perl::ECDSA::PublicKey ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

#cf. RFC 7517, page 25
sub test_jwk : Tests(1) {
    my $prkey = Crypt::Perl::ECDSA::PublicKey->new_by_curve_name(
        Crypt::Perl::BigInt->from_bytes( "\x04" . MIME::Base64::decode_base64url('MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4') . MIME::Base64::decode_base64url('4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM') ),
        'prime256v1',
    );

    my $pub_jwk = $prkey->get_struct_for_public_jwk();

    my $expected_pub = {
        kty => "EC",
        crv => "P-256",
        x => "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        y => "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    };

    is_deeply(
        $pub_jwk,
        $expected_pub,
        'get_struct_for_public_jwk()',
    ) or diag explain $pub_jwk;

    return;
}

sub test_subject_public_key : Tests(1) {
    my ($self) = @_;

    my $openssl_bin = $self->_get_openssl();

    my $key_path = "$FindBin::Bin/assets/prime256v1.key.public";

    my $plain = File::Slurp::read_file($key_path);
    my $pkcs8 = `$openssl_bin pkey -in $key_path -pubin -pubout`;
    die if $?;

    $_ = Crypt::Format::pem2der($_) for ($pkcs8, $plain);

    $_ = Crypt::Perl::ECDSA::Parse::public($_) for ($pkcs8, $plain);

    is_deeply(
        $pkcs8,
        $plain,
        'PKCS8 key parsed the same as a regular one',
    );

    return;
}

sub test_to_der_with_explicit_curve : Tests(1) {
    my $key_path = "$FindBin::Bin/assets/prime256v1_explicit.key.public";

    my $pkey_pem = File::Slurp::read_file($key_path);
    my $der1 = Crypt::Format::pem2der($pkey_pem);

    my $ecdsa = Crypt::Perl::ECDSA::Parse::public($pkey_pem);

    my $der2 = $ecdsa->to_der_with_explicit_curve();

    $_ = unpack('H*', $_) for $der2, $der1;

    is(
        $der2,
        $der1,
        'output DER matches the input',
    );

    return;
}

sub test_to_der_with_curve_name : Tests(1) {
    my $key_path = "$FindBin::Bin/assets/prime256v1.key.public";

    my $pkey_pem = File::Slurp::read_file($key_path);
    my $der1 = Crypt::Format::pem2der($pkey_pem);

    my $ecdsa = Crypt::Perl::ECDSA::Parse::public($pkey_pem);

    my $der2 = $ecdsa->to_der_with_curve_name();

    $_ = unpack('H*', $_) for $der2, $der1;

    is(
        $der2,
        $der1,
        'output DER matches the input',
    );

    return;
}

sub test_verify : Tests(2) {
    my ($self) = @_;

    SKIP: {
        my $openssl_bin = $self->_get_openssl();
        skip 'No OpenSSL binary!', 1 if !$openssl_bin;

        my $key_path = "$FindBin::Bin/assets/prime256v1.key.public";

        my $pkey_pem = File::Slurp::read_file($key_path);

        my $ecdsa = Crypt::Perl::ECDSA::Parse::public($pkey_pem);

        my $msg = 'Hello';

        my $sig = pack 'H*', '3046022100e3d248766709081d22f1c2762a79ac1b5e99edc2fe147420e1131cb207859300022100ad218584c31c55b2a15d1598b00f425bfad41b3f3d6a4eec620cc64dfc931848';

        is(
            $ecdsa->verify( $msg, $sig ),
            1,
            'verify() - positive',
        );

        my $bad_sig = $sig;
        $bad_sig =~ s<.\z><9>;

        is(
            $ecdsa->verify( $msg, $bad_sig ),
            0,
            'verify() - negative',
        );
    }

    return;
}

1;
