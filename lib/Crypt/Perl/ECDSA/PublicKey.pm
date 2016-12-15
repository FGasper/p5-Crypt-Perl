package Crypt::Perl::ECDSA::PublicKey;

=encoding utf-8

=head1 NAME

Crypt::Perl::ECDSA::PublicKey - object representation of ECDSA public key

=head1 SYNOPSIS

    #Use Parse.pm or a private key’s get_public_key()
    #rather #than instantiating this class directly.

    #This works even if the object came from a key file that doesn’t
    #contain the curve name.
    $pbkey->get_curve_name();

    if ($payload > ($pbkey->max_sign_bits() / 8)) {
        die "Payload too long!";
    }

    $pbkey->verify($payload, $sig) or die "Invalid signature!";

    #For JSON Web Algorithms (JWT et al.), cf. RFC 7518 page 8
    #This verifies against the appropriate SHA digest rather than
    #against the original message.
    $pbkey->verify_jwa($payload, $sig) or die "Invalid signature!";

    #Corresponding “der” methods exist as well.
    my $cn_pem = $pbkey->to_pem_with_curve_name();
    my $expc_pem = $pbkey->to_pem_with_explicit_curve();

    #----------------------------------------------------------------------

    #Includes “kty”, “crv”, “x”, and “y”.
    #Add in whatever else your application needs afterward.
    #
    #This will die() if you try to run it with a curve that
    #doesn’t have a known JWK “crv” value.
    #
    my $pub_jwk = $pbkey->get_struct_for_public_jwk();

    #Useful for JWTs
    my $jwt_alg = $pbkey->get_jwa_alg();

=head1 DISCUSSION

The SYNOPSIS above should be illustration enough of how to use this class.

=cut

use strict;
use warnings;

use parent qw( Crypt::Perl::ECDSA::KeyBase );

use Try::Tiny;

use Crypt::Perl::BigInt ();

use constant ASN1_PUBLIC => Crypt::Perl::ECDSA::KeyBase->ASN1_Params() . q<

    FG_Keydata ::= SEQUENCE {
        oid         OBJECT IDENTIFIER,
        parameters  EcpkParameters
    }

    ECPublicKey ::= SEQUENCE {
        keydata     FG_Keydata,
        publicKey   BIT STRING
    }
>;

use constant _PEM_HEADER => 'EC PUBLIC KEY';

#There’s no new_by_curve_name() method here because
#that logic in PrivateKey is only really useful for when we
#generate keys.

sub new {
    my ($class, $public, $curve_parts) = @_;

    if ( !try { $public->isa('Crypt::Perl::BigInt') } ) {
        $public = Crypt::Perl::BigInt->from_bytes($public);
    }

    my $self = {
        public => $public,
    };

    bless $self, $class;

    return $self->_add_params( $curve_parts );
}

sub _get_asn1_parts {
    my ($self, $curve_parts) = @_;

    return $self->__to_der(
        'ECPublicKey',
        ASN1_PUBLIC(),
        {
            publicKey => $self->{'public'}->as_bytes(),
            keydata => {
                oid => $self->OID_ecPublicKey(),
                parameters => $curve_parts,
            },
        },
    );
}

1;
