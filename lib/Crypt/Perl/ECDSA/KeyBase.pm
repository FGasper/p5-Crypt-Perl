package Crypt::Perl::ECDSA::KeyBase;

use strict;
use warnings;

use Call::Context ();
use Crypt::Format ();
use Module::Load ();

use Crypt::Perl::ASN1 ();
use Crypt::Perl::BigInt ();
use Crypt::Perl::Math ();
use Crypt::Perl::ECDSA::EC::Curve ();
use Crypt::Perl::ECDSA::EC::DB ();
use Crypt::Perl::ECDSA::EC::Point ();
use Crypt::Perl::ECDSA::ECParameters ();
use Crypt::Perl::ECDSA::Utils ();

use constant OID_ecPublicKey => '1.2.840.10045.2.1';

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

    my $half_len = (length $sig) / 2;

    my $r = substr($sig, 0, $half_len);
    my $s = substr($sig, $half_len);

    $_ = Crypt::Perl::BigInt->from_bytes($_) for ($r, $s);

    return $self->_verify($msg, $r, $s);
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

sub public_x_and_y {
    my ($self) = @_;

    Call::Context::must_be_list();

    my @xy = Crypt::Perl::ECDSA::Utils::split_G_or_public( $self->{'public'}->as_bytes() );

    return map { Crypt::Perl::BigInt->from_bytes($_) } @xy;
}

#----------------------------------------------------------------------

sub _verify {
    my ($self, $msg, $r, $s) = @_;

    if ($r >= 1 && $s >= 1) {
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

            my $u1 = ($e * $c) % $n;
            my $u2 = ($r * $c) % $n;

            my $point = $self->_G()->multiply($u1)->add( $Q->multiply($u2) );

            my $v = $point->get_x()->to_bigint() % $n;

            return 1 if $v == $r;
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
    my $nbytes = length $curve_hr->{'n'}->as_bytes();

#print "pad: $nbytes / " . length($bytes) . $/;
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

    return {
        ecParameters => {
            version => 1,
            fieldID => {
                fieldType => Crypt::Perl::ECDSA::ECParameters::OID_prime_field(),
                parameters => {
                    'prime-field' => $curve_hr->{'p'},
                },
            },
            curve => {
                a => $curve_hr->{'a'}->as_bytes(),
                b => $curve_hr->{'b'}->as_bytes(),
            },
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

#use Data::Dumper;
#print Dumper($data_hr);
#print $template;

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
