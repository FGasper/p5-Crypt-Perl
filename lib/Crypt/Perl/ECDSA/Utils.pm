package Crypt::Perl::ECDSA::Utils;

=encoding utf-8

=head1 NAME

Crypt::Perl::ECDSA::Utils

=head1 DISCUSSION

This interface is undocumented for now.

=cut

use strict;
use warnings;

use Crypt::Perl::X ();

#Splits the combined (uncompressed) generator or the public key
#into its two component halves (octet strings).
sub split_G_or_public {
    my ($bytes_str) = @_;

    die Crypt::Perl::X::create('Generic', "Only bytes, not “$bytes_str”!") if ref $bytes_str;

    my $gen_prefix = ord( substr $bytes_str, 0, 1);

    if ( $gen_prefix ne 0x04 ) {
        die Crypt::Perl::X::create('Generic', "Unrecognized generator or public key prefix/type ($gen_prefix)!");
    }

    #Should never happen, but.
    if ( !(length($bytes_str) % 2) ) {
        die Crypt::Perl::X::create('Generic', "Invalid generator or public key: length must be uneven" );
    }

    my $len = (length($bytes_str) - 1) / 2;

    return unpack( "x a$len a$len", $bytes_str );
}

1;
