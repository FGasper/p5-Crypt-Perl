package Crypt::Perl::ED25519;

use strict;
use warnings;

use Data::Dumper;

=encoding utf-8

=head1 NAME

=head1 SYNOPSIS

=head1 DESCRIPTION

Ported from L<https://github.com/digitalbazaar/forge/blob/master/lib/ed25519.js>.

=cut

use Digest::SHA;

use constant {
    PUBLIC_KEY_BYTE_LENGTH => 32,
    PRIVATE_KEY_BYTE_LENGTH => 64,
    SEED_BYTE_LENGTH => 32,
    SIGN_BYTE_LENGTH => 64,
    HASH_BYTE_LENGTH => 64,
};

use constant gf0 => (0) x 16;
use constant gf1 => ( 1, (0) x 15 );

use constant D => (
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203,
);

use constant D2 => (
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406,
);

use constant X => (
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169,
);

use constant Y => (
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
);

use constant L => (
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    (0) x 15, 0x10,
);

use constant I => (
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83,
);

# p is an array of arrays; s is an array of numbers
sub _scalarbase {
    my ($p, $s) = @_;

    my @q = ( [ X() ], [ Y() ], [ gf1() ], [ gf0() ] );

    _M( $q[3], [X()], [Y()] );

    _scalarmult($p, \@q, $s);
}

# p and q are arrays of arrays; s is an array of numbers
sub _scalarmult {
    my ($p, $q, $s) = @_;

    @{$p}[0 .. 3] = ( [ gf0() ], [ gf1() ], [ gf1() ], [ gf0() ] );

    my $b;

    for my $i ( reverse( 0 .. 255 ) ) {
        $b = ( $s->[ ( $i >> 3 ) | 0 ] >> ($i & 7) ) & 1;
        _cswap( $p, $q, $b );
        _add( $q, $p );
        _add( $p, $p );
        _cswap( $p, $q, $b );
    }

    return;
}

# p and q are arrays of numbers
sub _sel25519 {
    my ($p, $q, $b) = @_;

    my $c = ~($b - 1);

    for my $i ( 0 .. 15 ) {
        my $t = $c & ($p->[$i] ^ $q->[$i]);
        $p->[$i] ^= $t;
        $q->[$i] ^= $t;
    }
}

# p and q are arrays of arrays
sub _cswap {
    my ($p, $q, $b) = @_;

    for my $i ( 0 .. 3 ) {
        _sel25519( $p->[$i], $q->[$i], $b );
    }
}

sub _add {
    my ($p, $q) = @_;

    my $a = [ gf0() ];
    my $b = [ gf0() ];
    my $c = [ gf0() ];
    my $d = [ gf0() ];
    my $e = [ gf0() ];
    my $f = [ gf0() ];
    my $g = [ gf0() ];
    my $h = [ gf0() ];
    my $t = [ gf0() ];

    _Z($a, $p->[1], $p->[0]);
    _Z($t, $q->[1], $q->[0]);
    _M($a, $a, $t);
    _A($b, $p->[0], $p->[1]);
    _A($t, $q->[0], $q->[1]);
    _M($b, $b, $t);
    _M($c, $p->[3], $q->[3]);
    _M($c, $c, [ D2() ]);
    _M($d, $p->[2], $q->[2]);
    _A($d, $d, $d);
    _Z($e, $b, $a);
    _Z($f, $d, $c);
    _A($g, $d, $c);
    _A($h, $b, $a);

    _M($p->[0], $e, $f);
    _M($p->[1], $h, $g);
    _M($p->[2], $g, $f);
    _M($p->[3], $e, $h);
}

sub generate_key_pair {
    my (%opts) = @_;

    # The seed *is* the private part of the key. (?!?)
    my $seed = $opts{'seed'};

    if ($seed) {
        if (SEED_BYTE_LENGTH != length $seed) {
            die sprintf("Seed (%s) is not %d bytes!", $seed, SEED_BYTE_LENGTH());
        }
    }
    else {
        ...;
        $seed = _get_random_bytes(SEED_BYTE_LENGTH());  #XXX
    }

    # crypto_sign_keypair

    my @digest = _digest32($seed);

    my $p = [ map { [ gf0() ] } 0 .. 3 ];

    # private key is 32 bytes for private part
    # plus 32 bytes for the public part

    _scalarbase($p, \@digest);
    my $pk = _pack($p);

    return( [ unpack 'C*', $seed ], $pk );
}

sub _digest32 {
    my ($seed) = @_;

    my @digest = unpack 'C*', Digest::SHA::sha512($seed);
    $digest[0]  &= 0xf8;    #248
    $digest[31] &= 0x7f;    #127
    $digest[31] |= 0x40;    # 64

    return @digest;
}

# p is an array of arrays
sub _pack {
    my ($p) = @_;

    my $tx = [ gf0() ];
    my $ty = [ gf0() ];
    my $zi = [ gf0() ];

    _inv25519( $zi, $p->[2] );

    _M( $tx, $p->[0], $zi );
    _M( $ty, $p->[1], $zi );

    my $r = _pack25519($ty);

    $r->[31] ^= (_par25519($tx) << 7);

    return $r;
}

sub _inv25519 {
    my ($o, $i) = @_;

    my $c = [ @{$i}[0 .. 15] ];

    for my $a ( reverse( 0 .. 253 ) ) {
        _S($c, $c);

        next if $a == 2;
        next if $a == 4;

        _M( $c, $c, $i );
    }

    @{$o}[0 .. 15] = @{$c}[0 .. 15];

    return;
}

sub _pack25519 {
    my ($n) = @_;

    my $b;

    my $o = [];

    my $t = [ @{$n}[0 .. 15] ];

    my $m = [ gf0() ];

    _car25519($t) for 1 .. 3;

    for my $j (0, 1) {
        $m->[0] = $t->[0] - 0xffed;

        for my $i ( 1 .. 14 ) {
            $m->[$i] = $t->[$i] - 0xffff - (($m->[$i - 1] >> 16) & 1);
            $m->[$i - 1] &= 0xffff;
        }

        $m->[15] = $t->[15] - 0x7fff - (($m->[14] >> 16) & 1);

        $b = ($m->[15] >> 16) & 1;

        $m->[14] &= 0xffff;

        _sel25519( $t, $m, 1 - $b );
    }

    for my $i ( 0 .. 15 ) {
        $o->[2 * $i] = $t->[$i] & 0xff;
        $o->[2 * $i + 1] = $t->[$i] >> 8;
    }

    return $o;
}

sub _par25519 {
    my ($a) = @_;

    my $d = _pack25519($a);

    return $d->[0] & 1;
}

# o, a, and b are arrays of numbers
sub _M {
    my ($o, $a, $b) = @_;

    my @t = (0) x 31;

    for my $a_idx ( 0 .. 15 ) {
        my $v = $a->[$a_idx];
        $t[$a_idx + $_] += $v * $b->[$_] for 0 .. 15;
    }

    # $t->[15] left as-is
    for my $t_idx ( 0 .. 14 ) {
        $t[$t_idx] += 38 * $t[16 + $t_idx];
    }

    my ($c, $v);

    _car25519(\@t);
    _car25519(\@t);

    @{$o}[0 .. 15] = @t[0 .. 15];

    return;
}

sub _car25519 {
    my ($o) = @_;

    my $c = 1;
    my $v;

    for my $o_idx ( 0 .. 15 ) {
        $v = $o->[$o_idx] + $c + 65535;

        # c = Math.floor(v / 65536)
        $c = int( $v / 65536 );
        $c-- if $v < 0;

        # t0 = v - c * 65536
        $o->[$o_idx] = $v - ($c * 65536);
    }

    $o->[0] += $c - 1 + 37 * ($c - 1);

    return;
}

# o, a, and b are arrays of numbers
sub _A {
    my ($o, $a, $b) = @_;

    $o->[$_] = $a->[$_] + $b->[$_] for 0 .. 15;

    return;
}

# o, a, and b are arrays of numbers
sub _Z {
    my ($o, $a, $b) = @_;

    $o->[$_] = $a->[$_] - $b->[$_] for 0 .. 15;

    return;
}

sub _S { _M( $_[0], $_[1], $_[1] ) }

#----------------------------------------------------------------------

sub _reduce {
    my ($r) = @_;

    my @x;

    for my $i ( 0 .. 63 ) {
        $x[$i] = $r->[$i];
        $r->[$i] = 0;
    }
#print "reduce-x: @x\n";
#print "reduce-r: @$r\n";

    _modL( $r, \@x );

    return;
}

sub _modL {
    my ($r, $x) = @_;

    my ($k);

    for my $i ( reverse( 32 .. 63 ) ) {
        my $carry = 0;

        my ($j, $k);

        for (
            ($j = $i - 32), ($k = $i - 12);
            $j < $k;
            ++$j
        ) {
            $x->[$j] += $carry - 16 * $x->[$i] * (L())[$j - ($i - 32)];

            # originally “>> 8” rather than “/ 256”;
            # we need a floor(), too.
            $carry = int( ($x->[$j] + 128) / 256 );
            $carry-- if $x->[$j] < -128;

#print "$x->[$j] + 128 = " . ($x->[$j] + 128) . ", carry=$carry$/";
            $x->[$j] -= $carry * 256;
        }
#print "j,k,x: $j, $k, @$x\n";

        $x->[$j] += $carry;
        $x->[$i] = 0;
    }
#print "x1: @$x\n";

    my $carry = 0;

    for my $j ( 0 .. 31 ) {
        $x->[$j] += $carry - ($x->[31] >> 4) * (L())[$j];

        # originally “>> 8” rather than “/ 256”; we also need floor
        # $carry = $x->[$j] >> 8;
        $carry = int( $x->[$j] / 256 );
        $carry-- if $x->[$j] < 0;

#print "xj: $x->[$j]; carry: $carry\n";

        $x->[$j] &= 255;
    }
#print "x2: @$x\n";

    $x->[$_] -= $carry * (L())[$_] for 0 .. 31;

    for my $i ( 0 .. 31 ) {
        $x->[$i + 1] += $x->[$i] >> 8;
        $r->[$i] = $x->[$i] & 255;
    }

    return;
}

sub verify {
    my ($public_ar, $msg, $sig_ar) = @_;

    my @sm = @$sig_ar, unpack( 'C*', $msg );
    my @m = (0) x @sm;
    #my @t = (0) x 32;

    my @p = map { [ gf() ] } 1 .. 4;
    my @q = map { [ gf() ] } 1 .. 4;

    if ( _unpackneg( \@q, $public_ar ) ) {
        die "-1??";
    }

    @m = @sm;
    @m[ 32 .. 63 ] = @{$public_ar};

    my @h = Digest::SHA::sha512( pack 'C*', @m );
    _reduce(\@h);

    _scalarmult(\@p, \@q, \@h);

    my @latter_sm = @sm[32 .. $#sm];
    _scalarbase( \@q, \@latter_sm );
    @sm[32 .. $#sm] = @latter_sm;

    _add( \@p, \@q );
    my @t = _pack(\@p);

    my $n = @sm - SIGN_BYTE_LENGTH;

#  if(crypto_verify_32(sm, 0, t, 0)) {
#    for(i = 0; i < n; ++i) {
#      m[i] = 0;
#    }
#    return -1;
#  }
#
#  for(i = 0; i < n; ++i) {
#    m[i] = sm[i + 64];
#  }
#  mlen = n;
#return mlen;
}

sub sign {
    my ($private_ar, $public_ar, $msg) = @_;

    my @x = (0) x 64;

    my @p = map { [ gf0() ] } 1 .. 4;

    my @digest = unpack 'C*', Digest::SHA::sha512(pack 'C*', @$private_ar);
    $digest[0]  &= 0xf8;    #248
    $digest[31] &= 0x7f;    #127
    $digest[31] |= 0x40;    # 64

    my @sm = (0) x 32;
    push @sm, @digest[32 .. 63];
    push @sm, unpack( 'C*', $msg );

    my @r = unpack 'C*', Digest::SHA::sha512( pack 'C*', @sm[32 .. $#sm] );
    _reduce(\@r);
    _scalarbase( \@p, \@r );
    @sm[ 0 .. 31 ] = @{ _pack(\@p) };

    @sm[32 .. 63] = @{$public_ar};
#print "sm: @sm\n";

    my @h = unpack 'C*', Digest::SHA::sha512( pack 'C*', @sm );
    _reduce( \@h );
#print "reduced h @h\n";

    @x[0 .. 31] = @r[0 .. 31];

    for my $i ( 0 .. 31) {
        for my $j ( 0 .. 31 ) {
            $x[ $i + $j ] += $h[$i] * $digest[$j];
        }
    }

    my @latter_sm = @sm[32 .. $#sm];

    _modL( \@latter_sm, \@x );

    @sm[32 .. $#sm] = @latter_sm;

    return @sm[ 0 .. (SIGN_BYTE_LENGTH - 1) ];
}

1;
