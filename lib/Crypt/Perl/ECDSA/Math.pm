package Crypt::Perl::ECDSA::Math;

use strict;
use warnings;

use Crypt::Perl::BigInt ();

#A port of libtomcrypt’s mp_sqrtmod_prime()
#
#See also implementations at:
#   https://rosettacode.org/wiki/Tonelli-Shanks_algorithm
#
#See “Handbook of Applied Cryptography”, algorithms 3.34 and 3.36,
#for reference.
sub tonelli_shanks {
    my ($n, $p) = @_;

    _make_bigints($n, $p);

    return 0 if $n == 0;

    die "prime must be odd" if $p->beq(2);

    if (jacobi($n, $p) == -1) {
        die sprintf( "jacobi(%s, %s) must not be -1", $n->as_hex(), $p->as_hex());
    }

    die "prime must be odd!" if $p == 2;

    #HAC 3.36
    if ( $p->copy()->bmod(4)->beq(3) ) {
        return $n->copy()->bmodpow( $p->copy()->binc()->brsft(2), $p );
    }

    my $S = _bi(0);
    my $Q = $p - 1;
    while ( !($Q & 1) ) {
        $Q >>= 1;
        $S++;
    }

    my $Z = Crypt::Perl::BigInt->new(2);
    my $legendre;
    while (1) {
        last if jacobi($Z, $p) == -1;
        $Z->binc();
    }

    my $C = $Z->copy()->bmodpow($Q, $p);

    my $t1 = ($Q + 1) / 2;

    my $R = $n->copy()->bmodpow($t1, $p);

    my $T = $n->copy()->bmodpow($Q, $p);

    my $M = $S;

    while (1) {
        my $i = 0;
        $t1 = $T->copy();

        while (1) {
            last if $t1->is_one();
            $t1->bmodpow(2, $p);
            $i++;
        }

        if ($i == 0) {
            return $R;
        }

        $t1 = _bi(2)->bmodpow($M - $i - 1, $p);

        $t1 = $C->bmodpow($t1, $p);

        $C = $t1->copy()->bmodpow(2, $p);
        $R->bmul($t1)->bmod($p);
        $T->bmul($C)->bmod($p);
        $M = _bi($i);
    }
}

#cf. mp_jacobi()
sub jacobi {
    my ($a, $n) = @_;

    _make_bigints($a, $n);

    my $ret = 1;

    #This loop avoids deep recursion.
    while (1) {
        my ($ret2, $help) = _jacobi_backend($a, $n);

        $ret *= $ret2;

        if ($help) {
            ($a, $n) = @$help;
        }
        else {
            last;
        }
    }

    return $ret;
}

sub _make_bigints {
    ref || ($_ = _bi($_)) for @_;
}

sub _jacobi_backend {
    my ($a, $n) = @_;

    die "“a” can’t be negative!" if $a < 0;

    die "“n” must be positive!" if $n <= 0;

    #step 1
    if ($a == 0) {
        if ($n == 1) {
            return 1;
        }

        return 0;
    }

    #step 2
    if ($a == 1) {
        return 1;
    }

    #default
    my $s = 0;

    my $a1 = $a;
    my $k = _count_lsb($a1);

    $a1 >>= $k;

    #step 4
    if (($k & 1) == 0) {
        $s = 1;
    }
    else {
        my $residue = $n & 7;

        if ( $residue == 1 || $residue == 7 ) {
            $s = 1;
        }
        elsif ( $residue == 3 || $residue == 5 ) {
            $s = -1;
        }
    }

    #step 5
    if ( (($n & 3) == 3) && (($a1 & 3) == 3) ) {
        $s = 0 - $s;
    }

    if ($a1 == 1) {
        return $s;
    }

    my $p1 = $n % $a1;

    return( $s, [$p1, $a1] );
}

#cf. mp_cnt_lsb()
sub _count_lsb {
    my ($num) = @_;

    #sprintf('%b',$num) =~ m<(0*)\z>;
    $num->as_bin() =~ m<(0*)\z>;

    return length $1;
}

sub _bi { return Crypt::Perl::BigInt->new(@_) }

1;
