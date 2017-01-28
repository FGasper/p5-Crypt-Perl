package Crypt::Perl::ECDSA::KeyBase;

use strict;
use warnings;

use parent qw(
    Crypt::Perl::KeyBase
);

use Crypt::Format ();
use Module::Load ();

use Crypt::Perl::ASN1 ();
use Crypt::Perl::BigInt ();
use Crypt::Perl::Math ();
use Crypt::Perl::ECDSA::EC::Curve ();
use Crypt::Perl::ECDSA::EC::DB ();
use Crypt::Perl::ECDSA::EC::Point ();
use Crypt::Perl::ECDSA::ECParameters ();
use Crypt::Perl::ECDSA::NIST ();
use Crypt::Perl::ECDSA::Utils ();
use Crypt::Perl::X ();

use constant ASN1_SIGNATURE => q<
    SEQUENCE {
        r   INTEGER,
        s   INTEGER
    }
>;

use constant ASN1_Params => Crypt::Perl::ECDSA::ECParameters::ASN1_ECParameters() . q<
    EcpkParameters ::= CHOICE {
        namedCurve      OBJECT IDENTIFIER,
        ecParameters    ECParameters
    }
>;

use constant _JWK_THUMBPRINT_JSON_ORDER => qw( crv kty x y );

use constant JWA_DIGEST_prime256v1 => 'sha256';
use constant JWA_DIGEST_secp384r1 => 'sha384';
use constant JWA_DIGEST_secp521r1 => 'sha512';

use constant JWA_CURVE_ALG_prime256v1 => 'ES256';
use constant JWA_CURVE_ALG_secp384r1 => 'ES384';
use constant JWA_CURVE_ALG_secp521r1 => 'ES512';

#Expects $key_parts to be a hash ref:
#
#   version - AFAICT unused
#   private - BigInt or its byte-string representation
#   public  - ^^
#
sub new_by_curve_name {
    my ($class, $key_parts, $curve_name) = @_;

    #We could store the curve name on here if looking it up
    #in to_der_with_curve_name() proves prohibitive.
    return $class->new(
        $key_parts,

        #“Fake out” the $curve_parts attribute by recreating
        #the structure that ASN.1 would give from a named curve.
        {
            namedCurve => Crypt::Perl::ECDSA::EC::DB::get_oid_for_curve_name($curve_name),
        },
    );
}

#$msg has to be small enough that the key could have signed it.
#It’s probably a digest rather than the original message.
sub verify {
    my ($self, $msg, $sig) = @_;

    my $struct = Crypt::Perl::ASN1->new()->prepare(ASN1_SIGNATURE)->decode($sig);

    return $self->_verify($msg, @{$struct}{ qw( r s ) });
}

#cf. RFC 7518, page 8
sub verify_jwa {
    my ($self, $msg, $sig) = @_;

    my $dgst_cr = $self->_get_jwk_digest_cr();

    my $half_len = (length $sig) / 2;

    my $r = substr($sig, 0, $half_len);
    my $s = substr($sig, $half_len);

    $_ = Crypt::Perl::BigInt->from_bytes($_) for ($r, $s);

    return $self->_verify($dgst_cr->($msg), $r, $s);
}

sub to_der_with_curve_name {
    my ($self) = @_;

    return $self->_get_asn1_parts($self->_named_curve_parameters());
}

sub to_der_with_explicit_curve {
    my ($self) = @_;

    return $self->_get_asn1_parts($self->_explicit_curve_parameters());
}

sub to_pem_with_curve_name {
    my ($self) = @_;

    my $der = $self->to_der_with_curve_name();

    return Crypt::Format::der2pem($der, $self->_PEM_HEADER());
}

sub to_pem_with_explicit_curve {
    my ($self) = @_;

    my $der = $self->to_der_with_explicit_curve();

    return Crypt::Format::der2pem($der, $self->_PEM_HEADER());
}

sub max_sign_bits {
    my ($self) = @_;

    return $self->_get_curve_obj()->keylen();
}

sub get_curve_name {
    my ($self) = @_;

    return Crypt::Perl::ECDSA::EC::DB::get_curve_name_by_data( $self->_curve() );
}

sub get_struct_for_public_jwk {
    my ($self) = @_;

    my ($xb, $yb) = Crypt::Perl::ECDSA::Utils::split_G_or_public( $self->{'public'}->as_bytes() );

    Module::Load::load('MIME::Base64');

    return {
        kty => 'EC',
        crv => $self->_get_jwk_curve_name(),
        x => MIME::Base64::encode_base64url($xb),
        y => MIME::Base64::encode_base64url($yb),
    }
}

sub get_jwa_alg {
    my ($self) = @_;

    my $name = $self->get_curve_name();

    my $getter_cr = __PACKAGE__->can("JWA_CURVE_ALG_$name") or do {
        die sprintf( "“%s” knows of no JWA “alg” for the curve “%s”!", ref($self), $name);
    };

    return $getter_cr->();
}

#----------------------------------------------------------------------

sub _get_jwk_digest_cr {
    my ($self) = @_;

    my $name = $self->get_curve_name();

    my $getter_cr = $self->can("JWA_DIGEST_$name") or do {
        die sprintf( "“%s” knows of no digest to use for JWA with the curve “%s”!", ref($self), $name);
    };

    Module::Load::load('Digest::SHA');

    return Digest::SHA->can( $getter_cr->() );
}

sub _get_jwk_curve_name {
    my ($self) = @_;

    my $name = $self->get_curve_name();

    return Crypt::Perl::ECDSA::NIST::get_nist_for_curve_name($name);
}

sub _verify {
    my ($self, $msg, $r, $s) = @_;

    if ($r->bge(1) && $s->bge(1)) {
        my ($x, $y) = Crypt::Perl::ECDSA::Utils::split_G_or_public( $self->{'public'}->as_bytes() );
        $_ = Crypt::Perl::BigInt->from_bytes($_) for ($x, $y);

        my $curve = $self->_get_curve_obj();

        my $Q = Crypt::Perl::ECDSA::EC::Point->new(
            $curve,
            $curve->from_bigint($x),
            $curve->from_bigint($y),
        );

        my $e = Crypt::Perl::BigInt->from_bytes($msg);

        #----------------------------------------------------------------------

        my $n = $self->_curve()->{'n'};

        if ($r < $n && $s < $n) {
            my $c = $s->copy()->bmodinv($n);

            my $u1 = $e->copy()->bmul($c)->bmod($n);
            my $u2 = $r->copy()->bmul($c)->bmod($n);

            my $point = $self->_G()->multiply($u1)->add( $Q->multiply($u2) );

            my $v = $point->get_x()->to_bigint()->copy()->bmod($n);

            return 1 if $v->beq($r);
        }
    }

    return 0;
}

#return isa EC::Point
sub _G {
    my ($self) = @_;
    return $self->_get_curve_obj()->decode_point( @{$self->_curve()}{ qw( gx gy ) } );
}

sub _pad_bytes_for_asn1 {
    my ($self, $bytes) = @_;

    my $curve_hr = $self->_curve();
    my $nbytes = length $curve_hr->{'p'}->as_bytes();

    substr( $bytes, 0, 0 ) = ("\0" x ($nbytes - length $bytes));

    return $bytes;
}

sub _named_curve_parameters {
    my ($self) = @_;

    my $curve_name = $self->get_curve_name();

    return {
        namedCurve => Crypt::Perl::ECDSA::EC::DB::get_oid_for_curve_name($curve_name),
    };
}

sub _explicit_curve_parameters {
    my ($self) = @_;
    my $curve_hr = $self->_curve();

    my ($gx, $gy) = map { $_->as_bytes() } @{$curve_hr}{'gx', 'gy'};

    for my $str ( $gx, $gy ) {
        $str = $self->_pad_bytes_for_asn1($str);
    }

    my %curve = (
        a => $curve_hr->{'a'}->as_bytes(),
        b => $curve_hr->{'b'}->as_bytes(),
    );

    if ($curve_hr->{'seed'}) {
        $curve{'seed'} = $curve_hr->{'seed'}->as_bytes();
    }

    return {
        ecParameters => {
            version => 1,
            fieldID => {
                fieldType => Crypt::Perl::ECDSA::ECParameters::OID_prime_field(),
                parameters => {
                    'prime-field' => $curve_hr->{'p'},
                },
            },
            curve => \%curve,
            base => "\x{04}$gx$gy",
            order => $curve_hr->{'n'},
            cofactor => $curve_hr->{'h'},
        },
    };
}

sub __to_der {
    my ($self, $macro, $template, $data_hr) = @_;

    my $curve_hr = $self->_curve();

    my $nbytes = Crypt::Perl::Math::ceil( $curve_hr->{'n'} / 8 );

    my ($pub_x, $pub_y) = Crypt::Perl::ECDSA::Utils::split_G_or_public( $self->{'public'}->as_bytes() );

    for my $str ( $pub_x, $pub_y ) {
        $str = $self->_pad_bytes_for_asn1($str);
    }

    local $data_hr->{'publicKey'} = "\x04$pub_x$pub_y";

    Module::Load::load('Crypt::Perl::ASN1');
    my $asn1 = Crypt::Perl::ASN1->new()->prepare($template);

    return $asn1->find($macro)->encode( $data_hr );
}

#return isa EC::Curve
sub _get_curve_obj {
    my ($self) = @_;

    return $self->{'_curve_obj'} ||= Crypt::Perl::ECDSA::EC::Curve->new( @{$self->_curve()}{ qw( p a b ) } );
}

sub _add_params {
    my ($self, $params_struct) = @_;

    if (my $params = $params_struct->{'ecParameters'}) {
        $self->{'curve'} = Crypt::Perl::ECDSA::ECParameters::normalize($params);
    }
    else {
        $self->{'curve'} = $self->_curve_params_for_OID($params_struct->{'namedCurve'});
    }

    return $self;
}

sub _curve_params_for_OID {
    my ($self, $oid) = @_;

    return Crypt::Perl::ECDSA::EC::DB::get_curve_data_by_oid($oid);
}

sub _curve {
    my ($self) = @_;

    return $self->{'curve'} ||= $self->_curve_params_for_OID();
}

#----------------------------------------------------------------------

1;
