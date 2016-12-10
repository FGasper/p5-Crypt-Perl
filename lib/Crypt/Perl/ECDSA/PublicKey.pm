package Crypt::Perl::ECDSA::PublicKey;

use strict;
use warnings;

use parent qw( Crypt::Perl::ECDSA::KeyBase );

use Try::Tiny;

use Crypt::Perl::ASN1 ();
use Crypt::Perl::BigInt ();
use Crypt::Perl::PKCS8 ();

use constant OID_ecPublicKey => '1.2.840.10045.2.1';

use constant ASN1_PUBLIC => q<

    FG_Keydata ::= SEQUENCE {
        oid         OBJECT IDENTIFIER,
        parameters  EcpkParameters
    }

    ECPublicKey ::= SEQUENCE {
        keydata     FG_Keydata,
        publicKey   BIT STRING
    }
>;

sub new {
    my ($class, $der) = @_;

    Crypt::Perl::ToDER::ensure_der($der);

    my $asn1 = $class->_asn1();
    my $asn1_ec = $asn1->find('ECPublicKey');

    my $struct;
    try {
        $struct = $asn1_ec->decode($der);
    }
    catch {
        my $ec_err = $_;

        my $asn1_pkcs8 = $asn1->find('SubjectPublicKeyInfo');

        try {
            my $spk_struct = $asn1_pkcs8->decode($der);

            #It still might succeed, even if this is wrong, so don’t die().
            if ( $spk_struct->{'algorithm'}{'algorithm'} ne $class->OID_ecPublicKey() ) {
                warn "Unknown private key algorithm OID: “$spk_struct->{'algorithm'}{'algorithm'}”";
            }

            my $asn1_params = $asn1->find('EcpkParameters');
            my $params = $asn1_params->decode($spk_struct->{'algorithm'}{'parameters'});

            $struct = { publicKey => $spk_struct->{'subjectPublicKey'} };
            $struct->{'keydata'}{'parameters'} = $params;
        }
        catch {
            die "Failed to decode private key as either ECDSA native ($ec_err) or PKCS8 ($_)";
        };
    };

    my $self = {
        public => Crypt::Perl::BigInt->from_bytes( $struct->{'publicKey'}[0] ),
        public_bytes_r => \$struct->{'publicKey'}[0],
    };

    bless $self, $class;

    $self->_add_params( $struct->{'keydata'}{'parameters'} );

    return $self;
}

sub to_der_with_curve_name {
    my ($self) = @_;
}

sub _asn1 {
    my ($self) = @_;

    my $template = join("\n", $self->ASN1_Params(), $self->ASN1_PUBLIC(), Crypt::Perl::PKCS8::ASN1());

    return Crypt::Perl::ASN1->new()->prepare($template);
}

1;
