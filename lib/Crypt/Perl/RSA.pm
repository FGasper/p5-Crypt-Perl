package Crypt::Perl::RSA;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Crypt::Perl::RSA - RSA in pure Perl (really!)

=head1 SYNOPSIS

    my $prkey1 = Crypt::Perl::RSA::Parse::private($pem_or_der);
    my $pbkey1 = Crypt::Perl::RSA::Parse::public($pem_or_der);

    #----------------------------------------------------------------------

    my $prkey = Crypt::Perl::RSA::Generate::generate(2048);

    my $der = $prkey->to_der();
    my $der2 = $prkey->to_pem();

    #----------------------------------------------------------------------

    my $msg = 'My message';

    my $sig = $prkey->sign_RS256($msg);

    die 'Wut' if !$prkey->verify_RS256($msg, $sig);

    die 'Wut' if !$pbkey->verify_RS256($msg, $sig);

=head1 DISCUSSION

See the documentation for L<Crypt::Perl::RSA::PublicKey> and
L<Crypt::Perl::RSA::PrivateKey> for more on what these interfaces
can do.

NOTE: The RSA logic here is ported from Kenji Urushima’s
L<jsrsasign|http://kjur.github.io/jsrsasign/>.

=head1 SECURITY

RSA is safe as long as factorization is “hard”. As computers get faster, RSA
keys have needed to get bigger and bigger to maintain the “difficulty” of
factoring the key’s modulus. RSA will eventually no longer be viable toward
this end: as RSA keys get bigger, the
security advantage of increasing their size diminishes.

=head1 SPEED

Key generation is pretty slow—potentially unacceptably so for general use.
It can be made faster by having an XS-based backend available for
L<Math::BigInt> and L<Bytes::Random::Secure::Tiny>, but it’ll still be pretty
pokey. The difficulty rests in prime number generation, which is handled by
L<Math::ProvablePrime>.

=head1 TODO

This minimal set of functionality can be augmented as feature requests come in.
Ideas:

=over 4

=item * Support signature schemes besides PKCS #1 v1.5.

=item * Use faster prime-number-finder logic if it’s available.

=back

=cut

1;
