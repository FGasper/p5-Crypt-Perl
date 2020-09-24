package Crypt::Perl::ECDSA::Deterministic;

=encoding utf-8

=head1 NAME

Crypt::Perl::ECDSA::Deterministic

=head1 DISCUSSION

This module implements L<RFC 6979|https://tools.ietf.org/html/rfc6979>’s
algorithm for deterministic ECDSA signatures.

=cut

use strict;
use warnings;

use Digest::HMAC ();

use Crypt::Perl::Math ();

our $q;
our $qlen;
our $qlen_bytelen;

sub generate_k {
    my ($order, $key, $msg, $hashfunc, $blksize) = @_;

    local $q = $order;
    local $qlen = length $order->to_bin();
    local $qlen_bytelen = Crypt::Perl::Math::ceil( $qlen / 8 );

    my $privkey_bytes = $key->to_bytes();
    substr( $privkey_bytes, 0, 0, "\0" x ($qlen_bytelen - length $privkey_bytes) );

    my $h1 = $hashfunc->($msg);
    # printf "h1: %v.02x\n", $h1;
    # printf "x: %v.02x\n", $privkey_bytes;

    # printf "bits2octets(h1): %v.02x\n", bits2octets($h1);

    my $hashlen = length $h1;

    my $V = "\x01" x $hashlen;

    my $K = "\x00" x $hashlen;

    $K = Digest::HMAC::hmac(
        $V . "\0" . $privkey_bytes . bits2octets($h1),
        $K,
        $hashfunc,
        $blksize,
    );
    # printf "K after step d: %v.02x\n", $K;

    $V = Digest::HMAC::hmac( $V, $K, $hashfunc, $blksize );
    # printf "V after step E: %v.02x\n", $V;

    $K = Digest::HMAC::hmac(
        $V . "\1" . $privkey_bytes . bits2octets($h1),
        $K,
        $hashfunc,
        $blksize,
    );
    # printf "K after step F: %v.02x\n", $K;

    $V = Digest::HMAC::hmac( $V, $K, $hashfunc, $blksize );
    # printf "V after step G: %v.02x\n", $V;

    my $k;

    while (1) {
        my $T = q<>;

        while (1) {
            $V = Digest::HMAC::hmac( $V, $K, $hashfunc, $blksize );
            $T .= $V;

            last if length(Math::BigInt->from_bytes($T)->to_bin()) >= $qlen;
        }
        # printf "new T: %v.02x\n", $T;
        # print Math::BigInt->from_bytes($T)->to_bin() . $/;

        $k = bits2int($T, $qlen);

        if ($k >= 1 && $k < $order) {
            # print "got good k\n";
            # TODO: determine $r’s suitability
            last;
        }

        # printf "bad k: %v.02x\n", $k->to_bytes();

        $K = Digest::HMAC::hmac( $V . "\0", $K, $hashfunc, $blksize );
        # printf "new K: %v.02x\n", $K;
        $V = Digest::HMAC::hmac( $V, $K, $hashfunc, $blksize );
        # printf "new V: %v.02x\n", $V;
    }

    return $k;
}

sub bits2int {
    my ($bits, $qlen) = @_;

    my $blen = 8 * length $bits;
    $bits = Math::BigInt->from_bytes($bits)->to_bin();

    if ($qlen < $blen) {
        substr($bits, -($blen - $qlen)) = q<>;
    }

    return Math::BigInt->from_bin($bits);
}

sub int2octets {
    my $octets = shift()->to_bytes();

    if (length($octets) > $qlen_bytelen) {
        substr( $octets, 0, -$qlen_bytelen ) = q<>;
    }
    elsif (length($octets) < $qlen_bytelen) {
        substr( $octets, 0, 0, "\0" x ($qlen_bytelen - length $octets) );
    }

    return $octets;
}

sub bits2octets {
    my ($bits) = @_;
    my $z1 = bits2int($bits, $qlen);

    my $z2 = ($z1 % $q);

    return int2octets($z2, $qlen);
}

1;
