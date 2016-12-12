package Crypt::Perl::RSA::PrivateKey;

use strict;
use warnings;

use parent qw(
    Class::Accessor::Fast
    Crypt::Perl::RSA::KeyBase
);

use File::Spec ();

use Crypt::Perl::Load ();

BEGIN {
    __PACKAGE__->mk_ro_accessors(
        qw(
        version
        publicExponent
        privateExponent
        prime1
        prime2
        exponent1
        exponent2
        coefficient
        )
    );

    *E = \&publicExponent;
    *D = \&privateExponent;

    *P = \&prime1;
    *Q = \&prime2;

    *DP = \&exponent1;
    *DQ = \&exponent2;

    *QINV = \&coefficient;
}

sub sign_RS256 {
    my ($self, $msg) = @_;

    return $self->_sign($msg, 'Digest::SHA', 'sha256', 'PKCS1_v1_5');
}

sub sign_RS384 {
    my ($self, $msg) = @_;

    return $self->_sign($msg, 'Digest::SHA', 'sha384', 'PKCS1_v1_5');
}

sub sign_RS512 {
    my ($self, $msg) = @_;

    return $self->_sign($msg, 'Digest::SHA', 'sha512', 'PKCS1_v1_5');
}

sub get_public_key {
    my ($self) = @_;

    Crypt::Perl::Load::module('Crypt::Perl::RSA::PublicKey');

    return Crypt::Perl::RSA::PublicKey->new( {
        modulus => $self->{'modulus'},
        exponent => $self->{'publicExponent'},
    } );
}

sub to_der {
    my ($self) = @_;

    return $self->_to_der('RSAPrivateKey');
}

sub _sign {
    my ($self, $msg, $hash_module, $hasher, $scheme) = @_;

    Crypt::Perl::Load::module($hash_module);

    my $dgst = $hash_module->can($hasher)->($msg);

    my $sig;

    if ($scheme eq 'PKCS1_v1_5') {
        Crypt::Perl::Load::module('Crypt::Perl::RSA::PKCS1_v1_5');

        my $sig_length = $self->get_modulus_byte_length();

        #The encoded length equals the length, in bytes,
        #of the key’s modulus.
        my $eb = Crypt::Perl::RSA::PKCS1_v1_5::encode(
            $dgst,
            $hasher,
            $sig_length,
        );

        #printf "PERL: %v02x\n", $eb;
        #print "mod byte length: " . Crypt::Perl::RSA::get_modulus_byte_length($key_obj) . $/;

        my $x = Crypt::Perl::BigInt->from_hex( unpack 'H*', $eb );

        $sig = $self->_transform($x)->as_bytes();

        substr( $sig, 0, 0 ) = "\0" x ($sig_length - length $sig);
    }
    else {
        die "Unknown scheme: “$scheme”";
    }

    return $sig;
}

#RSA’s encryption/decryption operation.
#This function is based on _modPow() in forge’s js/rsa.js.
#
#Returns a BigInt.
sub _transform {
    my ($self, $x) = @_;

    my $key_bytes_length = $self->get_modulus_byte_length();

    #cryptographic blinding
    my $r;
    do {
        $r = Crypt::Perl::BigInt->from_hex(
            Crypt::Perl::RNG::bytes_hex( $key_bytes_length ),
        );
    } while ($r >= $self->N()) || ($r->bgcd($self->N()) != 1);

    $x *= $r->copy()->bmodpow($self->E(), $self->N());
    $x %= $self->N();

    #calculate xp and xq
    my $xp = ($x % $self->P())->bmodpow($self->DP(), $self->P());
    my $xq = ($x % $self->Q())->bmodpow($self->DQ(), $self->Q());

    #xp must be larger than xq to avoid signed bit usage
    while ($xp < $xq) {
        $xp += $self->P();
    }

    my $y = $xp - $xq;
    $y *= $self->QINV();
    $y %= $self->P();
    $y *= $self->Q();
    $y += $xq;

    #remove effect of random for cryptographic blinding
    $y *= $r->bmodinv($self->N());
    $y %= $self->N();

    return $y;
}

1;
