package t::Crypt::Perl::PKCS10;

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
    NeedsOpenSSL
);

use Crypt::Perl::ECDSA::Generate ();
use Crypt::Perl::PK ();
use Crypt::Perl::X509::Name ();

use Crypt::Perl::PKCS10 ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

sub new {
    my ($class) = @_;

    my $self = $class->SUPER::new();

    $self->num_method_tests(
        'test_new__ecdsa',
        (3 + @{ [ keys %Crypt::Perl::X509::Name::_OID ] }) * @{ [ $self->_KEY_TYPES_TO_TEST() ] },
    );

    return $self;
}

sub _KEY_TYPES_TO_TEST {
    return (
        1024,
        2048,
        'secp224k1',
        'brainpoolP256r1',
        'secp384r1',
        'secp521r1',
        'prime239v1',
        'brainpoolP320r1',
        'brainpoolP512r1',
    );
}

sub test_new__ecdsa : Tests() {
    my ($self) = @_;

    my $ossl_bin = $self->_get_openssl();

    for my $type ( $self->_KEY_TYPES_TO_TEST() ) {
        my $key;

        my $print_type;

        if ($type =~ m<\A[0-9]>) {
            $key = Crypt::Perl::PK::parse_key( scalar qx<$ossl_bin genrsa $type> );
            $print_type = "RSA ($type-bit)";
        }
        else {
            $key = Crypt::Perl::ECDSA::Generate::by_name($type);
            $print_type = "ECDSA ($type)";
        }

        my $pkcs10 = Crypt::Perl::PKCS10->new(
            key => $key,
            subject => [
                map { $_ => "the_$_" } keys %Crypt::Perl::X509::Name::_OID
            ],
            attributes => [
                [ 'challengePassword' => 'iNsEcUrE' ],
                [ 'extensionRequest',
                    [ 'subjectAltName',
                        dNSName => 'felipegasper.com',
                        dNSName => 'gasperfelipe.com',
                    ],
                ],
            ],
        );

        my ($fh, $fpath) = File::Temp::tempfile( CLEANUP => 1 );
        print {$fh} $pkcs10->to_pem() or die $!;
        close $fh;

        my $text = qx<$ossl_bin req -text -noout -in $fpath>;

        for my $subj_part (sort keys %Crypt::Perl::X509::Name::_OID) {
            like( $text, qr/=the_\Q$subj_part\E/, "$print_type: $subj_part" );
        }

        like( $text, qr/challengePassword.*iNsEcUrE/, "$print_type: challengePassword" );
        like( $text, qr<DNS:felipegasper\.com>, "$print_type: SAN 1" );
        like( $text, qr<DNS:gasperfelipe\.com>, "$print_type: SAN 2" );
    }

    return;
}

1;
