package Crypt::Perl::ECDSA;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Crypt::Perl::ECDSA - Elliptic curve cryptography in pure Perl

=head1 SYNOPSIS

    my $key1 = Crypt::Perl::ECDSA::key($public_or_private__pem_or_der);

    my $key2 = Crypt::Perl::ECDSA::key_pem($public_or_private);
    my $key3 = Crypt::Perl::ECDSA::key_der($public_or_private);

    my $pub_key1 = Crypt::Perl::ECDSA::public_key($pem_or_der);
    my $prv_key1 = Crypt::Perl::ECDSA::private_key($pem_or_der);

    my $pub_key2 = Crypt::Perl::ECDSA::public_key_pem($pem);
    my $prv_key2 = Crypt::Perl::ECDSA::private_key_pem($pem);

    my $pub_key3 = Crypt::Perl::ECDSA::public_key_der($der);
    my $prv_key3 = Crypt::Perl::ECDSA::private_key_der($der);

    #----------------------------------------------------------------------

    my $prkey_by_name = Crypt::Perl::ECDSA::Generate::by_name('secp521r1');

    my $prkey_by_curve = Crypt::Perl::ECDSA::Generate::by_explicit_curve(
        {
            p => ..., #isa Crypt::Perl::BigInt
            a => ..., #isa Crypt::Perl::BigInt
            b => ..., #isa Crypt::Perl::BigInt
            n => ..., #isa Crypt::Perl::BigInt
            h => ..., #isa Crypt::Perl::BigInt
            gx => ..., #isa Crypt::Perl::BigInt
            gy => ..., #isa Crypt::Perl::BigInt
        },
    );

    my $der = $prkey->to_der_with_curve_name();

    my $der2 = $prkey->to_der_with_explicit_curve_name();

    #----------------------------------------------------------------------

    my $msg = 'My message';

    my $hash = Digest::SHA::sha256($msg);

    my $sig = $private->sign($hash);

    die 'Wut' if !$private->verify($hash, $sig);

    die 'Wut' if !$public->verify($hash, $sig);

=head1 DISCUSSION

See the documentation for C<Crypt::Perl::ECDSA::PublicKey> and
C<Crypt::Perl::ECDSA::PrivateKey> for discussions of what these interfaces
can do.

NOTE: The ECDSA logic here is ported from Kenji Urushima’s L<jsrsasign|http://kjur.github.io/jsrsasign/>.

=head1 TODO

=over 4

=item * It would be great to support characteristic-two curves.

=back

=head1 HANDY OPENSSL ONE-LINERS

These were so useful in testing (and, unlike the corresponding RSA commands,
not immediately obvious to remember) that I think it useful to include them
here.

    #Generate a key (prime256v1 curve)
    openssl ecparam -genkey -name prime256v1 -noout

    #Same operation, but include the curve parameters explicitly
    openssl ecparam -genkey -name prime256v1 -noout -param_enc explicit

    #Verify a hash signature
    #NB: OpenSSL can’t verify a signature of *just* a message;
    #it always hashes the message when it verifies.
    openssl dgst -sha256 -prverify $key_path -signature $sigfile $msgfile

=cut

use Crypt::Format ();

use Crypt::Perl::ASN1 ();

#Accepts public or prive, pem or der
sub key {
    my ($given) = @_;
}

#Accepts public or private
sub key_pem {
    my ($given) = @_;
}

#Accepts public or private
sub key_der {
    my ($given) = @_;

    my $exc = $@;
    my $key = eval { new_private_der($given) };
    #if (
}

#Accepts pem or der
sub public_key {
    my ($given) = @_;

    return _is_pem($given) ? new_public_pem($given) : new_public_der($given);
}

#Accepts pem or der
sub private_key {
    my ($given) = @_;

    return _is_pem($given) ? new_private_pem($given) : new_private_der($given);
}

sub public_key_pem {
    return new_private_der( Crypt::Format::pem2der(shift) );
}

sub public_key_der {
    require Crypt::Perl::ECDSA::PublicKey;
    return Crypt::Perl::ECDSA::PublicKey->new(@_);
}

sub private_key_pem {
    return new_private_der( Crypt::Format::pem2der(shift) );
}

sub private_key_der {
    require Crypt::Perl::ECDSA::PrivateKey;
    return Crypt::Perl::ECDSA::PrivateKey->new(@_);
}

#----------------------------------------------------------------------

sub _is_pem { ... }

1;
