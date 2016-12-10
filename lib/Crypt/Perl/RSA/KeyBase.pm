package Crypt::Perl::RSA::KeyBase;

use strict;
use warnings;

use parent qw(Class::Accessor::Fast);

use Crypt::Perl::BigInt ();
use Crypt::Perl::Load ();
use Crypt::Perl::RNG ();

BEGIN {
    __PACKAGE__->mk_ro_accessors('modulus');

    *N = \&modulus;
}

#i.e., modulus length, in bits
sub size {
    my ($self) = @_;

    return length( $self->modulus()->as_bin() ) - 2;
}

sub get_modulus_byte_length {
    my ($self) = @_;

    return length $self->N()->as_bytes();

    #return( ( length( $self->N()->as_hex() ) - 2 ) / 2 );
}

sub verify_RS256 {
    my ($self, $msg, $sig) = @_;

    return $self->_verify($msg, $sig, 'Digest::SHA', 'sha256', 'PKCS1_v1_5');
}

sub verify_RS384 {
    my ($self, $msg, $sig) = @_;

    return $self->_verify($msg, $sig, 'Digest::SHA', 'sha384', 'PKCS1_v1_5');
}

sub verify_RS512 {
    my ($self, $msg, $sig) = @_;

    return $self->_verify($msg, $sig, 'Digest::SHA', 'sha512', 'PKCS1_v1_5');
}

#----------------------------------------------------------------------

sub _to_der {
    my ($self, $macro) = @_;

    Crypt::Perl::Load::module('Crypt::Perl::ASN1');
    Crypt::Perl::Load::module('Crypt::Perl::RSA::Template');
    my $asn1 = Crypt::Perl::ASN1->new()->prepare(
        Crypt::Perl::RSA::Template::get_template('INTEGER'),
    );

    return $asn1->find($macro)->encode( { %$self } );
}

sub _verify {
    my ($self, $message, $signature, $hash_module, $hasher, $scheme) = @_;

    Crypt::Perl::Load::module($hash_module);

    my $digest = $hash_module->can($hasher)->($message);

    my $y = Crypt::Perl::BigInt->from_hex( unpack 'H*', $signature );

    #This modifies $y, but it doesn’t matter here.
    my $x = $y->bmodpow( $self->E(), $self->N() );

    #Math::BigInt will strip off the leading zero that PKCS1_v1_5 requires,
    #so let’s put it back first of all.
    my $octets = "\0" . $x->as_bytes();

    #printf "OCTETS - %v02x\n", $octets;

    if ($scheme eq 'PKCS1_v1_5') {
        my $key_bytes_length = $self->get_modulus_byte_length();
        if (length($octets) != $key_bytes_length) {
            die sprintf( "Invalid PKCS1_v1_5 length: %d (should be %d)", length($octets), $key_bytes_length );
        }

        Crypt::Perl::Load::module('Crypt::Perl::RSA::PKCS1_v1_5');
        return $digest eq Crypt::Perl::RSA::PKCS1_v1_5::decode($octets, $hasher);
    }

    die "Unknown scheme: “$scheme”";
}

1;
