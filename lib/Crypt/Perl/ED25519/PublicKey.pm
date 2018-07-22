package Crypt::Perl::ED25519::PublicKey;

use strict;
use warnings;

use parent qw( Crypt::Perl::ED25519::KeyBase );

sub new {
    my ($class, $pub) = @_;

    return bless {
        _public => $pub,
        _public_ar => [ unpack 'C*', $pub ],
    }, $class;
}

1;
