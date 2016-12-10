package Crypt::Perl::ECDSA::Parser;

use strict;
use warnings;

use Try::Tiny;

use Crypt::Perl::ASN1 ();
use Crypt::Perl::PKCS8 ();
use Crypt::Perl::ToDER ();
use Crypt::Perl::ECDSA::ECParameters ();
use Crypt::Perl::ECDSA::PrivateKey ();
use Crypt::Perl::ECDSA::PublicKey ();

sub private {
    my ($pem_or_der) = @_;

    Crypt::Perl::ToDER::ensure_der($pem_or_der);

    my $asn1 = _private_asn1();
    my $asn1_ec = $asn1->find('ECPrivateKey');

    my $struct;
    try {
        $struct = $asn1_ec->decode($pem_or_der);
    }
    catch {
        my $ec_err = $_;

        my $asn1_pkcs8 = $asn1->find('PrivateKeyInfo');

        try {
            my $pk8_struct = $asn1_pkcs8->decode($pem_or_der);

            #It still might succeed, even if this is wrong, so don’t die().
            if ( $pk8_struct->{'privateKeyAlgorithm'}{'algorithm'} ne Crypt::Perl::ECDSA::PublicKey::OID_ecPublicKey() ) {
                warn "Unknown private key algorithm OID: “$pk8_struct->{'privateKeyAlgorithm'}{'algorithm'}”";
            }

            my $asn1_params = $asn1->find('EcpkParameters');
            my $params = $asn1_params->decode($pk8_struct->{'privateKeyAlgorithm'}{'parameters'});

            $struct = $asn1_ec->decode($pk8_struct->{'privateKey'});
            $struct->{'parameters'} = $params;
        }
        catch {
            die "Failed to decode private key as either ECDSA native ($ec_err) or PKCS8 ($_)";
        };
    };

    my $key_parts = {
        version => $struct->{'version'},
        private => Crypt::Perl::BigInt->from_bytes($struct->{'privateKey'}),
        public => Crypt::Perl::BigInt->from_bytes($struct->{'publicKey'}[0]),
    };

    return Crypt::Perl::ECDSA::PrivateKey->new($key_parts, $struct->{'parameters'});
}

#This is not the standard ASN.1 template as found in RFC 5915,
#but it seems to generate equivalent results.
#
#The specific patterns for ECDSA explicit parameters seem to be
#locked behind some silly thing that someone wants me to pay for.
#TODO: Find out this information.
use constant ASN1_PRIVATE => q<

    ECPrivateKey ::= SEQUENCE {
        version         INTEGER,
        privateKey      OCTET STRING,
        parameters      [0] EXPLICIT EcpkParameters OPTIONAL,
        publicKey       [1] EXPLICIT BIT STRING
    }
>;

use constant ASN1_Params => Crypt::Perl::ECDSA::ECParameters::ASN1_ECParameters() . q<
    EcpkParameters ::= CHOICE {
        namedCurve      OBJECT IDENTIFIER,
        ecParameters    ECParameters
    }
>;

sub _private_asn1 {
    my ($self) = @_;

    my $template = join("\n", ASN1_Params(), ASN1_PRIVATE(), Crypt::Perl::PKCS8::ASN1());

    return Crypt::Perl::ASN1->new()->prepare($template);
}

1;
