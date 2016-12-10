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

use JSON ();
use MIME::Base64 ();

use Crypt::Perl::RSA::Parser ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

sub new {
    my ($class, @args) = @_;

    my $self = $class->SUPER::new(@args);

    $self->_load_tests();

    local $@;
    $self->{'_has_ossl'} = eval { require Crypt::OpenSSL::RSA };

    $self->num_method_tests( 'do_RS256_tests', 5 * @{ $self->{'_tests'} } );

    return $self;
}

sub _load_tests {
    my ($self) = @_;

    open my $rfh, '<', "$FindBin::Bin/assets/RS256.json";
    $self->{'_tests'} = do { local $/; <$rfh> };
    close $rfh;

    $self->{'_tests'} = JSON::decode_json( $self->{'_tests'} );

    return;
}

sub _display_raw {
    return sprintf( '%v02x', $_[0] );
}

sub check_RS384_and_RS512 : Tests(6) {
    my ($self) = @_;

    my $largest_pem = $self->{'_tests'}->[-1][1];
    my $key = Crypt::Perl::RSA::Parser->new()->private($largest_pem);

    for my $alg ( qw( RS384 RS512 ) ) {
        my $message = rand;

        my $signature = $key->can("sign_$alg")->( $key, $message );

        is(
            $key->can("verify_$alg")->( $key, $message, $signature ),
            1,
            "$alg: Perl verified Perl’s signature",
        );

        is(
            $key->can("verify_$alg")->( $key, $message, $key->can("sign_$alg")->( $key, "00$message" ) ),
            q<>,
            "$alg: Perl non-verified a wrong signature",
        );

        SKIP: {
            skip 'No Crypt::OpenSSL::RSA; skipping', 1 if !$self->{'_has_ossl'};

            my $rsa = Crypt::OpenSSL::RSA->new_private_key($largest_pem);
            $alg =~ m<([0-9]+)> or die "huh? $alg";
            $rsa->can("use_sha$1_hash")->($rsa);
            ok(
                $rsa->verify( $message, $signature ),
                "$alg: OpenSSL verified Perl’s signature",
            );
        }
    }

    return;
}

sub do_RS256_tests : Tests() {
    my ($self) = @_;

    for my $t ( @{ $self->{'_tests'} } ) {
        my ($label, $key_pem, $message, $sig_b64) = @$t;

        my $ossl_sig = MIME::Base64::decode($sig_b64);

        my $key = Crypt::Perl::RSA::Parser->new()->private($key_pem);

        is(
            $key->verify_RS256( $message, $ossl_sig ),
            1,
            "$label: Perl verified OpenSSL’s signature",
        );

        my $signature = $key->sign_RS256( $message );

        is(
            _display_raw($signature),
            _display_raw($ossl_sig),
            "$label: Perl’s signature is as expected",
        ) or do { diag $message; diag $key_pem };

        is(
            $key->verify_RS256( $message, $signature ),
            1,
            "$label: Perl verified Perl’s signature",
        );

        my $mangled_sig = reverse $signature;

        dies_ok(
            sub { $key->verify_RS256( $message, $mangled_sig ) },
            "$label: mangled signature non-verification",
        );

        SKIP: {
            skip 'No Crypt::OpenSSL::RSA; skipping', 1 if !$self->{'_has_ossl'};

            my $rsa = Crypt::OpenSSL::RSA->new_private_key($key_pem);
            $rsa->use_sha256_hash();
            ok(
                $rsa->verify( $message, $signature ),
                "$label: OpenSSL verified Perl’s signature",
            );
        }
    }

    return;
}
