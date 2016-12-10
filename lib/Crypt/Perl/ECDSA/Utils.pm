package Crypt::Perl::ECDSA::Utils;

use strict;
use warnings;

#Splits the combined (uncompressed) generator or the public key
#into its two component halves.
sub split_G_or_public {
    my ($bytes_str) = @_;

    die "Only bytes, not “$bytes_str”!" if ref $bytes_str;

    my $gen_prefix = ord( substr $bytes_str, 0, 1);

    if ( $gen_prefix ne 0x04 ) {
        die "Unrecognized generator or public key prefix/type ($gen_prefix)!";
    }

    #Should never happen, but.
    if ( !(length($bytes_str) % 2) ) {
        die "Invalid generator or public key: length must be uneven";
    }

    my $len = (length($bytes_str) - 1) / 2;

    return unpack( "x a$len a$len", $bytes_str );
}

1;
