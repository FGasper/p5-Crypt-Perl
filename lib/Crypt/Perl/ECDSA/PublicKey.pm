package Crypt::Perl::ECDSA::PublicKey;

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
