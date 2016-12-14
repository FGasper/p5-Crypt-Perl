package t::Crypt::Perl::ECDSA::PrivateKey;

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

use lib "$FindBin::Bin/../lib";

use Crypt::Perl::ECDSA::Generate ();
use Crypt::Perl::ECDSA::Parse ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

BEGIN {
    *_CURVE_NAMES = \&OpenSSL_Control::curve_names;
}

sub new {
    my ($class, @args) = @_;

    my $self = $class->SUPER::new(@args);

    $self->num_method_tests( 'test_sign', 2 * @{ [ $class->_CURVE_NAMES() ] } );

    return $self;
}

sub test_get_public_key : Tests(1) {
    my $key_path = "$FindBin::Bin/assets/prime256v1.key";

    my $key_str = File::Slurp::read_file($key_path);

    my $key_obj = Crypt::Perl::ECDSA::Parse::private($key_str);

    my $public = $key_obj->get_public_key();

    my $msg = 'Hello';

    my $sig = $key_obj->sign($msg);

    ok( $public->verify($msg, $sig), 'get_public_key() produces a working public key' );

    return;
}

sub test_to_der : Tests(2) {
    my $key_path = "$FindBin::Bin/assets/prime256v1.key";

    my $key_str = File::Slurp::read_file($key_path);

    my $key_obj = Crypt::Perl::ECDSA::Parse::private($key_str);

    my $der = $key_obj->to_der_with_curve_name();

    my $ossl_der = Crypt::Format::pem2der($key_str);
    is(
        $der,
        $ossl_der,
        'to_der_with_curve_name() yields same output as OpenSSL',
    ) or do { diag unpack( 'H*', $_ ) for ($der, $ossl_der) };

    #----------------------------------------------------------------------

    $key_path = "$FindBin::Bin/assets/prime256v1_explicit.key";
    $key_str = File::Slurp::read_file($key_path);
    $key_obj = Crypt::Perl::ECDSA::Parse::private($key_str);

    my $explicit_der = $key_obj->to_der_with_explicit_curve();
    $ossl_der = Crypt::Format::pem2der($key_str);

    is(
        $explicit_der,
        $ossl_der,
        'to_der_with_explicit_curve() matches OpenSSL, too',
    ) or do { diag unpack( 'H*', $_ ) for ($der, $ossl_der) };

    #print Crypt::Format::der2pem($explicit_der, 'EC PRIVATE KEY') . $/;

    return;
}

sub test_sign : Tests() {
    my ($self) = @_;

    my $openssl_bin = $self->_get_openssl();

    my $msg = 'Hello';

    #Use SHA1 since it’s the smallest digest that the latest OpenSSL accepts.
    my $dgst = Digest::SHA::sha1($msg);
    my $digest_alg = 'sha1';

    for my $curve ( _CURVE_NAMES() ) {
        for my $param_enc ( qw( named_curve explicit ) ) {

            SKIP: {
                note "$curve ($param_enc)";

                my $dir = File::Temp::tempdir(CLEANUP => 1);

                my $key_path = "$dir/key";

                system(
                    $openssl_bin, 'ecparam',
                    '-genkey',
                    '-noout',
                    -name => $curve,
                    -out => $key_path,
                    -param_enc => $param_enc,
                );
                die if $?;

                my $pkey_pem = File::Slurp::read_file($key_path);

                my $ecdsa;
                try {
                    $ecdsa = Crypt::Perl::ECDSA::Parse::private($pkey_pem);
                }
                catch {
                    my $ok = try { $_->isa('Crypt::Perl::X::ECDSA::CharacteristicTwoUnsupported') };
                    $ok ||= try { $_->isa('Crypt::Perl::X::ECDSA::NoCurveForOID') };

                    skip $_->to_string(), 1 if $ok;

                    local $@ = $_;
                    die;
                };

                #my $hello = $ecdsa->sign('Hello');
                #note unpack( 'H*', $hello );
                #note explain [ map { $_->as_hex(), $_->bit_length() } values %{ Crypt::Perl::ASN1->new()->prepare(Crypt::Perl::ECDSA::KeyBase::ASN1_SIGNATURE())->decode( $hello ) } ];

                #note "Key Prv: " . $ecdsa->{'private'}->as_hex();
                #note "Key Pub: " . $ecdsa->{'public'}->as_hex();

                try {
                    my $signature = $ecdsa->sign($dgst);

                    note "Sig: " . unpack('H*', $signature);

                    my $ok = OpenSSL_Control::verify_private(
                        $pkey_pem,
                        $msg,
                        $digest_alg,
                        $signature,
                    );

                    ok( $ok, "$curve, $param_enc parameters: OpenSSL binary verifies our digest signature for “$msg” ($digest_alg)" );
                }
                catch {
                    if ( try { $_->isa('Crypt::Perl::X::TooLongToSign') } ) {
                        skip $_->to_string(), 1;
                    }

                    local $@ = $_;
                    die;
                };
            }
        }
    }

    return;
}

sub test_jwa : Tests(6) {
    my ($self) = @_;

    for my $curve ( qw( prime256v1 secp384r1 secp521r1 ) ) {
        my $msg = rand;
        note "Message: [$msg]";

        $curve =~ m<([0-9]+)> or die '??';
        my $dgst = Digest::SHA::sha256($msg);

        my $key = Crypt::Perl::ECDSA::Generate::by_name($curve);
        note $key->to_pem_with_curve_name();

        my $sig = $key->sign_jwa($dgst);
        note( "Signature: " . unpack 'H*', $sig );

        is(
            $key->verify_jwa($dgst, $sig),
            1,
            "$curve: self-verify",
        );

        SKIP: {
            eval 'require Crypt::PK::ECC' or skip 'No Crypt::PK::ECC', 1;

            my $pk = Crypt::PK::ECC->new( \($key->to_pem_with_curve_name()) );
            ok(
                $pk->verify_message_rfc7518($sig, $msg, 'sha256'),
                "$curve: Crypt::PK::ECC verifies what we produced",
            );
        }
    }
}

sub test_verify : Tests(2) {
    my ($self) = @_;

    SKIP: {
        my $openssl_bin = $self->_get_openssl();
        skip 'No OpenSSL binary!', 1 if !$openssl_bin;

        my $key_path = "$FindBin::Bin/assets/prime256v1.key";

        my $pkey_pem = File::Slurp::read_file($key_path);

        my $ecdsa = Crypt::Perl::ECDSA::Parse::private($pkey_pem);

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
