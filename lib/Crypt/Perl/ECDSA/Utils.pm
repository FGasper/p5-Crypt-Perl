package Crypt::Perl::ECDSA::Utils;

=encoding utf-8

=head1 NAME

Crypt::Perl::ECDSA::Utils

=head1 DISCUSSION

This interface is undocumented for now.

=cut

use strict;
use warnings;

#Splits the combined (uncompressed) generator or the public key
#into its two component halves (octet strings).
sub split_G_or_public {
    my ($bytes_str) = @_;

    die "Only bytes, not “$bytes_str”!" if ref $bytes_str;

    my $gen_prefix = ord( substr $bytes_str, 0, 1);

    if ( $gen_prefix ne 0x04 ) {
        die "Unrecognized point prefix/type ($gen_prefix)!";
    }

    #Should never happen, but.
    if ( !(length($bytes_str) % 2) ) {
        die "Invalid generator or public key: length must be uneven";
    }

    my $len = (length($bytes_str) - 1) / 2;

    return unpack( "x a$len a$len", $bytes_str );
}

sub compress_point {
    my ($pub_bin) = @_;

    if (substr($pub_bin, 0, 1) ne "\x04") {
        die( sprintf "Invalid point to compress: %v.02x", $pub_bin );
    }

    my $first_octet = (chr( substr $pub_bin, -1 ) % 2) ? "\x03" : "\x02";

    my ($xb) = split_G_or_public( $pub_bin );

    return( $first_octet . $xb );
}

#$pub_bin is a string; $p/$a/$b are BigInt
#returns a string
sub decompress_point {
    my ($cpub_bin, $p, $a, $b) = @_;

    my $y_is_even = 0;
    my $octet1 = substr($cpub_bin, 0, 1);
    if ($octet1 eq "\x02") {
        $y_is_even = 1;
    }
    elsif ($octet1 ne "\x03") {
        die( sprintf "Invalid point to decompress: %v.02x", $cpub_bin );
    }

    #http://stackoverflow.com/questions/17171542/algorithm-for-elliptic-curve-point-compression
    #The following don’t seem to follow from the general elliptic curve formula, but hey.
    #also: https://en.wikipedia.org/wiki/Quadratic_residue#Prime_or_prime_power_modulus
    my $a_p = $a->copy()->bsub($p);
    my $pident = $p->copy()->binc()->brsft(2);

    my $x = Crypt::Perl::BigInt->from_bytes(substr $cpub_bin, 1);
    my $y = $x->copy()->bmodpow(3, $p);

    my $t2 = $x->copy()->bmodpow($a, $p);
    $y->badd($t2)->badd($b);

    #$y->bsqrt()->bmod($p);

#    my $y = $x->copy()->bpow(3)->badd( $x->copy()->bmul($a_p) );
#    $y->badd($b)->bmodpow($pident, $p);
#
    if (!!$y_is_even eq !!$y->is_odd()) {
        $y->bsub($p)->bneg();
    }

print "P: " . $p->as_hex() . $/;
print "A: " . $a->as_hex() . $/;
print "B: " . $b->as_hex() . $/;
print "X: " . $x->as_hex() . $/;
print "Y ($y_is_even): " . $y->as_hex() . $/;

    return join(
        q<>,
        "\x04",
        pad_bytes_for_asn1(substr($cpub_bin, 1), $p),
        pad_bytes_for_asn1($y->as_bytes(), $p),
    );
}

sub pad_bytes_for_asn1 {
    my ($bytes, $p) = @_;

    my $nbytes = length $p->as_bytes();

    substr( $bytes, 0, 0 ) = ("\0" x ($nbytes - length $bytes));

    return $bytes;
}

1;
