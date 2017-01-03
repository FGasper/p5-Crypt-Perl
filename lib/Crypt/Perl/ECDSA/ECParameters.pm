package Crypt::Perl::ECDSA::ECParameters;

=encoding utf-8

=head1 NAME

Crypt::Perl::ECDSA::ECParameters - Parse RFC 3279 explicit curves

=head1 DISCUSSION

This interface is undocumented for now.

=cut

use strict;
use warnings;

use Crypt::Perl::BigInt ();
use Crypt::Perl::ECDSA::Utils ();
use Crypt::Perl::X ();

use constant OID_prime_field => '1.2.840.10045.1.1';
use constant OID_characteristic_two_field => '1.2.840.10045.1.2';

use constant EXPORTABLE => qw( p a b n h gx gy );

#cf. RFC 3279
use constant ASN1_ECParameters => q<
    Trinomial ::= INTEGER

    Pentanomial ::= SEQUENCE {
        k1  INTEGER,
        k2  INTEGER,
        k3  INTEGER
    }

    FG_Basis_Parameters ::= CHOICE {
        gnBasis NULL,
        tpBasis Trinomial,
        ppBasis Pentanomial
    }

    Characteristic-two ::= SEQUENCE {
        m           INTEGER,
        basis       OBJECT IDENTIFIER,
        parameters  FG_Basis_Parameters
    }

    FG_Field_Parameters ::= CHOICE {
        prime-field         INTEGER,    -- p
        characteristic-two  Characteristic-two
    }

    FieldID ::= SEQUENCE {
        fieldType   OBJECT IDENTIFIER,
        parameters  FG_Field_Parameters
    }

    FieldElement ::= OCTET STRING
    -- FieldElement ::= INTEGER

    Curve ::= SEQUENCE {
        a           FieldElement,
        b           FieldElement,
        seed        BIT STRING OPTIONAL
    }

    ECPoint ::= OCTET STRING

    ECPVer ::= INTEGER

    -- Look for this.
    ECParameters ::= SEQUENCE {
        version         ECPVer,     -- always 1
        fieldID         FieldID,
        curve           Curve,
        base            ECPoint,    -- generator
        order           INTEGER,    -- n
        cofactor        INTEGER     -- h
    }
>;

#This must return the same information as
#Crypt::Perl::ECDSA::EC::DB::get_curve_data_by_oid().
sub normalize {
    my ($parsed_or_der) = @_;

    my $params;
    if (ref $parsed_or_der) {
        $params = $parsed_or_der;
    }
    else {
        die 'TODO';
    }

    my $field_type = $params->{'fieldID'}{'fieldType'};
    if ($field_type ne OID_prime_field() ) {
        if ($field_type eq OID_characteristic_two_field() ) {
            die Crypt::Perl::X::create('ECDSA::CharacteristicTwoUnsupported');
        }

        die "Unknown field type OID: “$field_type”";
    }

    my %curve = (
        p => $params->{'fieldID'}{'parameters'}{'prime-field'},
        a => $params->{'curve'}{'a'},
        b => $params->{'curve'}{'b'},
        n => $params->{'order'},
        h => $params->{'cofactor'},
    );

    @curve{'gx', 'gy'} = Crypt::Perl::ECDSA::Utils::split_G_or_public( $params->{'base'} );

    $_ = Crypt::Perl::BigInt->from_bytes($_) for @curve{qw( a b gx gy )};

    if ( $params->{'curve'}{'seed'} ) {
        $curve{'seed'} = Crypt::Perl::BigInt->from_bytes($params->{'curve'}{'seed'});
    }

    #Ensure that numbers like 0 and 1 are represented as BigInt, too.
    ref || ($_ = Crypt::Perl::BigInt->new($_)) for @curve{qw( p n h )};

    return \%curve;
}

#----------------------------------------------------------------------

sub _asn1 {
    my ($class) = @_;

    return Crypt::Perl::ASN1->new()->prepare($class->ASN1_ECParameters())->find('ECParameters');
}

1;
