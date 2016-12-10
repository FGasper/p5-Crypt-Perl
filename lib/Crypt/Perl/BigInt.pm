package Crypt::Perl::BigInt;

use strict;
use warnings;

#Even though Crypt::Perl intends to be pure Perl, there’s no reason
#not to use faster computation methods when they’re available.
use Math::BigInt try => 'GMP,Pari,FastCalc';

#To test pure Perl speed, comment out the above and enable:
#use Math::BigInt;

use parent -norequire => 'Math::BigInt';

sub from_bytes {
    my $class = shift;

    return $class->from_hex( unpack 'H*', $_[0] );
}

sub as_bytes {
    my ($self) = @_;

    die "Negatives ($self) can’t convert to bytes!" if $self < 0;

    my $hex = $self->as_hex();

    #Ensure that we have an even number of hex digits.
    if (length($hex) % 2) {
        substr($hex, 1, 1) = q<>;   #just remove the “x” of “0x”
    }
    else {
        substr($hex, 0, 2) = q<>;   #remove “0x”
    }

    return pack 'H*', $hex;
}

sub bit_length {
    my ($self) = @_;

    #Probably faster than 1 + $self->copy()->blog(2) …
    return( length($self->as_bin()) - 2 );
}

1;
