package Crypt::Perl;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Crypt::Perl - Cryptography in Pure Perl

=head1 DESCRIPTION

Just as it sounds: cryptography with no XS dependences! This is useful in
environments where you want to encrypt things but may not have access to
other tools that do this work like OpenSSL, C<CryptX>, etc. Of course,
if you do have access to one of those tools, they may suit your purpose
better.

See submodules for usage examples of:

=over 4

=item * Key generation

=item * Key parsing

=item * Signing

=item * Signature verification

=back

=head1 SUPPORTED ALGORITHMS

=over 4

=item * RSA

=item * ECDSA (including all curves from OpenSSL 1.0.2j)

=back

=head1 SECURITY

B<NO GUARANTEES!!!> So far this is just my own effort—and a port of existing
(likely also un-audited) logic at that. There has been no formal security
review. I did find L<one security problem|https://github.com/kjur/jsrsasign/issues/221>
in one of the source libraries; there may well be more.

That said, I am B<reasonably> confident that this is a “good enough” effort
for the intended circumstance (i.e., no access to other tools). Patches are
always welcome! :)

=head1 SPEED

It ain’t fast. :) That said, most operations here are reasonably quick.
This code does take advantage of XS-based backends for C<Math::BigInt> and
C<Bytes::Random::Secure::Tiny> where available.

=head1 TODO

There are TODO items listed in the submodules; the following are general
to the entire distribution.

=over 4

=item * Security audit. A check against L<OpenSSL|http://openssl.org> or
L<LibTomCrypt|http://www.libtom.org/LibTomCrypt/> would be awesome. I found
OpenSSL overly confusing to read, and I didn’t think to check LibTomCrypt
until I had solved the major problems.

=item * Add more tests.

=item * Make it faster :)

=back

=head1 ACKNOWLEDGEMENTS

Much of the logic here is taken from Kenji Urushima’s L<jsrsasign|https://github.com/kjur/jsrsasign>.
The RSA prime number generation logic comes from my own L<Math::ProvablePrime>
(itself being a port of a Python algorithm that I found).

Most of the tests depend on the near-ubiquitous OpenSSL.

1;
