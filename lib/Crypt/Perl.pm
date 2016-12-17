package Crypt::Perl;

use strict;
use warnings;

our $VERSION = 0.02;

=encoding utf-8

=head1 NAME

Crypt::Perl - Cryptography in Pure Perl

=head1 DESCRIPTION

Just as it sounds: cryptography with no non-core XS dependencies!
This is useful if you don’t have access to
other tools that do this work like L<OpenSSL|http://openssl.org>, L<CryptX>,
etc. Of course, if you do have access to one of those tools, they may suit
your purpose better.

See submodules for usage examples of:

=over 4

=item * Key generation

=item * Key parsing

=item * Signing & verification

=item * Encryption & decryption

=back

=head1 SUPPORTED ALGORITHMS

=over 4

=item * L<RSA|Crypt::Perl::RSA>

=item * L<ECDSA|Crypt::Perl::ECDSA>

=back

=head1 SECURITY

B<NO GUARANTEES!!!> So far this is just my own effort—and a port of existing
(likely also un-audited) logic at that.
B<There has been no formal security review.>
L<I did find one security problem|https://github.com/kjur/jsrsasign/issues/221>
in one of the source libraries; there may well be more.

That said, I am B<reasonably> confident that this is a “good enough” effort
for the intended circumstance (i.e., no access to other tools). Patches are
always welcome! :)

=head1 SPEED

Most operations here are reasonably quick, but certain ones (e.g., RSA
key generation) are pretty slow. Depending on your use case, this may or may
not be workable for you. It will always, of course, be slower than C-based
implementations like OpenSSL or L<LibTomCrypt|http://www.libtom.org/LibTomCrypt/>.
This code does take advantage of XS-based backends for modules like
L<Math::BigInt> and L<Bytes::Random::Secure::Tiny> where available.

=head1 TODO

There are TODO items listed in the submodules; the following are general
to the entire distribution.

=over 4

=item * Security audit. A check against OpenSSL or LibTomCrypt
would be awesome. I find OpenSSL overly confusing to read, and
I didn’t think to check LibTomCrypt until I had solved the major problems.

=item * Document the exception system so that applications can use it.

=item * Add more tests.

=item * Make it faster :)

=back

=head1 ACKNOWLEDGEMENTS

Much of the logic here comes from Kenji Urushima’s L<jsrsasign|https://github.com/kjur/jsrsasign>.

Most of the tests depend on the near-ubiquitous L<OpenSSL|http://openssl.org>,
without which the Internet would be a very, very different reality from
what we know!

=head1 LICENSE

This library is licensed under the same license as Perl.

=head1 AUTHOR

Felipe Gasper (FELIPE)

=cut

1;
