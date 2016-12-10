package Crypt::Perl::RSA::Math;

use strict;
use warnings;

use Crypt::Perl::BigInt ();
use Crypt::Perl::RNG ();

sub ceil {
    my ($num) = @_;

    return int($num) + int( !!($num - int $num) );
}

#could be faster; see JS implementation?
sub create_big_random {
    my ($limit) = @_;

    my $lim_bytes;
    if (ref($limit) && (ref $limit)->isa('Math::BigInt')) {
        $lim_bytes = length($limit->as_hex()) - 2;
    }
    else {
        $lim_bytes = length sprintf '%x', $limit;
    }

    $lim_bytes /= 2;

    my $r;
    do {
        $r = Crypt::Perl::BigInt->from_hex( Crypt::Perl::RNG::bytes_hex($lim_bytes) );
    } while $r > $limit;

    return $r;
}

sub create_random_bit_length {
    my ($length) = @_;

    my $num_str = Crypt::Perl::RNG::bit_string($length);

    #Set the least and greatest bits to be 1.
    substr($num_str, -1, 1, '1');
    substr($num_str, 0, 1, '1');

    return Crypt::Perl::BigInt->from_bin($num_str);
}

my @lowprimes = ( 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997 );
my $lplim = (1 << 26) / $lowprimes[-1];

use constant DV => 268435456;

#jsrsasign ext/jsbn2
sub mod_int {
    my ($this, $n) = @_;

    return 0 if $n <= 0;

    my $d = DV / $n;

    my $s = ($this < 0) ? -1 : 0;
    my $r = ($s < 0) ? ($n - 1) : 0;

    if ($this) {
        if ($d == 0) {
            $r = ($this & 0x0fffffff) % $n;
        }
        else {
            my $t = ceil( $this->bit_length / 28 );
            for my $i ( reverse( 0 .. ($t-1) ) ) {
                my $this_i = ($this >> (28 * $i)) & 0x0fffffff;
                $r = $d * $r + $this_i;
                $r %= $n;
            }
        }
    }

    return $r;
}

#jsrsasign/ext/jsbn2
sub is_probable_prime {
    my ($num, $t) = @_;

    my $i;
    my $x = $num;   #originally abs($num), but we don’t need that here (?)

    if ($x < $lowprimes[-1]) {
        return scalar grep { $x == $_ } @lowprimes;
    }

    return 0 if !($x % 2);

    for my $i ( 1 .. $#lowprimes ) {
        my $m = $lowprimes[$i];
        my $j = $i + 1;

        while ( $j < @lowprimes && $m < $lplim ) {
            $m *= $lowprimes[$j++];
        }

        $m = mod_int($x, $m);

        while ($i < $j) {
            if ( $m % $lowprimes[$i++] == 0 ) {
                return 0;
            }
        }
    }

    #return miller_rabin($x, $t);
    return 1;
}

1;
