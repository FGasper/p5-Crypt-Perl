package Crypt::Perl::ECDSA::Parser;

=encoding utf-8

=head1 NAME

Crypt::Perl::ECDSA::Parser - ECDSA key parsing

=head1 SYNOPSIS

    use Crypt::Perl::ECDSA::Parser ();

    #These accept either DER or PEM, native format or PKCS8.
    #
    my $prkey = Crypt::Perl::ECDSA::Parser::private($buffer);
    my $pbkey = Crypt::Perl::ECDSA::Parser::public($buffer);

=cut

use strict;
use warnings;

use Try::Tiny;

use Crypt::Perl::ASN1 ();
use Crypt::Perl::Load ();
use Crypt::Perl::PKCS8 ();
use Crypt::Perl::ToDER ();
use Crypt::Perl::ECDSA::ECParameters ();

sub private {
    my ($pem_or_der) = @_;

    Crypt::Perl::Load::module('Crypt::Perl::ECDSA::PrivateKey');

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
            if ( $pk8_struct->{'privateKeyAlgorithm'}{'algorithm'} ne Crypt::Perl::ECDSA::PrivateKey->OID_ecPublicKey() ) {
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

sub public {
    my ($pem_or_der) = @_;

    Crypt::Perl::Load::module('Crypt::Perl::ECDSA::PublicKey');

    Crypt::Perl::ToDER::ensure_der($pem_or_der);

    my $asn1 = _public_asn1();
    my $asn1_ec = $asn1->find('ECPublicKey');

    my $struct;
    try {
        $struct = $asn1_ec->decode($pem_or_der);
    }
    catch {
        my $ec_err = $_;

        my $asn1_pkcs8 = $asn1->find('SubjectPublicKeyInfo');

        try {
            my $spk_struct = $asn1_pkcs8->decode($pem_or_der);

            #It still might succeed, even if this is wrong, so don’t die().
            if ( $spk_struct->{'algorithm'}{'algorithm'} ne Crypt::Perl::ECDSA::PublicKey->OID_ecPublicKey() ) {
                warn "Unknown private key algorithm OID: “$spk_struct->{'algorithm'}{'algorithm'}”";
            }

            my $asn1_params = $asn1->find('EcpkParameters');
            my $params = $asn1_params->decode($spk_struct->{'algorithm'}{'parameters'});

            $struct = { publicKey => $spk_struct->{'subjectPublicKey'} };
            $struct->{'keydata'}{'parameters'} = $params;
        }
        catch {
            die "Failed to decode public key as either ECDSA native ($ec_err) or PKCS8 ($_)";
        };
    };

    return Crypt::Perl::ECDSA::PublicKey->new(
        $struct->{'publicKey'}[0],
        $struct->{'keydata'}{'parameters'},
    );
}

sub _private_asn1 {
    my $template = join("\n", Crypt::Perl::ECDSA::PrivateKey->ASN1_PRIVATE(), Crypt::Perl::PKCS8::ASN1());

    return Crypt::Perl::ASN1->new()->prepare($template);
}

sub _public_asn1 {
    my $template = join("\n", Crypt::Perl::ECDSA::PublicKey->ASN1_PUBLIC(), Crypt::Perl::PKCS8::ASN1());

    return Crypt::Perl::ASN1->new()->prepare($template);
}

1;
