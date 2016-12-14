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

    #Probably only useful for trying out a custom curve?
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

=item * I

=back

=head1 SECURITY

The security advantages of elliptic-curve cryptography (ECC) are a matter of
some controversy. While the math itself is apparently bulletproof, there are
varying opinions about the integrity of the various curves that are recommended
for ECC. Some believe that some curves contain “backdoors” that would allow
L<NIST|https://www.nist.gov> to sniff a transmission. For more information,
look at L<http://safecurves.cr.yp.to>.

That said, RSA will eventually no longer be viable: as RSA keys get bigger, the
security advantage of increasing their size diminishes.

This framework “has no opinion” regarding which curves you use; it ships all
of the prime-field curves that (L<OpenSSL|http://openssl.org>) includes and
works with any of them. You can try out custom curves as well.

=head1 TODO

This minimal set of functionality can be augmented as feature requests come in.
Patches are welcome—particularly with tests!

In particular, it would be great to support characteristic-two curves, though
almost everything seems to expect the prime-field variety.
OpenSSL is the only implementation I know of that
supports characteristic-two.)

=cut

1;
