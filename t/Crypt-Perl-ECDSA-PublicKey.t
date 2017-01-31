package t::Crypt::Perl::ECDSA::PublicKey;

use strict;
use warnings;

BEGIN {
    if ( $^V ge v5.10.1 ) {
        require autodie;
    }
}

use FindBin;
use lib "$FindBin::Bin/../lib";

use Test::More;
use Test::NoWarnings;
use Test::Deep;
use Test::Exception;

use Crypt::Format ();
use Digest::SHA ();
use File::Slurp ();
use File::Temp ();
use MIME::Base64 ();

use lib "$FindBin::Bin/lib";

use OpenSSL_Control ();

use parent qw(
    Test::Class
);

use Crypt::Perl::ECDSA::EC::DB ();
use Crypt::Perl::ECDSA::Parse ();
use Crypt::Perl::ECDSA::PublicKey ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

sub test_compressed : Tests(1) {
    my $pem = <<END;
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMad6ebreKzqt8jP0GAuzqclgwUMi4jscUJ53jqYmr7GoAoGCCqGSM49
AwEHoUQDQgAERWiv/yjXvsCl0pGfNJ/qV5ya42dAu8LcZxQY8/q15BJbo09fc7es
ddpYiQoziP/IVhwoJz2xFbzJSGeYCfzmeA==
-----END EC PRIVATE KEY-----
END

#----------------------------------------------------------------------
#    my $pubx_hex = '024568afff28d7bec0a5d2919f349fea579c9ae36740bbc2dc671418f3fab5e412';
#
#    my $need_y = '5ba34f5f73b7ac75da58890a3388ffc8561c28273db115bcc948679809fce678';
#
#    my $priv_hex = 'c69de9e6eb78aceab7c8cfd0602ecea72583050c8b88ec714279de3a989abec6';
#
    my $x = '4568afff28d7bec0a5d2919f349fea579c9ae36740bbc2dc671418f3fab5e412';
    my $a = 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc';
    my $b = '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b';
    my $p = 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff';
#----------------------------------------------------------------------

#    my $p = 'fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d';
#    my $a = '00';
#    my $b = '05';
#    my $x = '2bc04ac1bd74c1f27ce7d5e78aa8f71935a67f06245eaf932c26ca2e';

    my $need_y = 'b6ae47c402eece6d369a665d52bff4f3b60ed5ce3f708834e24d21dc';

    $_ = Crypt::Perl::BigInt->from_hex($_) for ($x, $a, $b, $p);

    #http://stackoverflow.com/questions/17171542/algorithm-for-elliptic-curve-point-compression
    #The following don’t seem to follow from the general elliptic curve formula, but hey.
    #also: https://en.wikipedia.org/wiki/Quadratic_residue#Prime_or_prime_power_modulus
#    $a->bsub($p);
#    my $pident = $p->copy()->binc()->brsft(2);
#
#    my $y = $x->copy()->bpow(3)->badd($x->copy()->bmul($a))->badd($b)->bmodpow($pident, $p);
#    if (substr($pubx_hex, 0, 2) eq '02' && $y->is_odd()) {
#        #$y = $p->copy()->bsub($y);
#        $y->bsub($p)->bneg();
#    }

#    my ($octet1, $y_is_even);
#    $octet1 = substr($pubx_hex, 0, 2);
#    if ($octet1 eq "02") {
#        $y_is_even = 1;
#    }
#    elsif ($octet1 ne "03") {
#        die( sprintf "Invalid point to decompress: %v.02x", $pubx_hex );
#    }
my $y_is_even = 1;

    my $a_p = $a->copy()->bsub($p);

    my $pident = $p->copy()->binc()->brsft(2);
#print "a/p: " . $a_p->as_hex() . $/;
#print "pident: " . $pident->as_hex() . $/;

#    my $y = $x->copy()->bpow(3)->badd( $x->bmul($a_p) );
#    $y->badd($b)->bmodpow($pident, $p);
#
#    if (!!$y_is_even eq !!$y->is_odd()) {
#        $y->bsub($p)->bneg();
#    }

    my $y = $x->copy()->bmodpow(3, $p);

    my $t2 = $x->copy()->bmul($a)->bmod($p);
    $y->badd($t2)->badd($b);
    $t2 = _tonelli_shanks( $y, $p );

    if (!!$y_is_even eq !!$y->is_even()) {
        $y = $t2->bmod($p);
    }
    else {
        $y = ($p - $t2);
        $y->bmod($p);
    }

    print $y->as_hex() . $/;

    return;
}

sub test_jacobi : Tests(34) {
    my @t = (

        #From: https://en.wikipedia.org/wiki/Legendre_symbol
        [ 0, 3 => 0 ],
        [ 1, 3 => 1 ],
        [ 2, 3 => -1 ],
        [ 0, 5 => 0 ],
        [ 1, 5 => 1 ],
        [ 2, 5 => -1 ],
        [ 3, 5 => -1 ],
        [ 4, 5 => 1 ],
        [ 0, 7 => 0 ],
        [ 1, 7 => 1 ],
        [ 2, 7 => 1 ],
        [ 3, 7 => -1 ],
        [ 4, 7 => 1 ],
        [ 5, 7 => -1 ],
        [ 6, 7 => -1 ],
        [ 0, 11 => 0 ],
        [ 1, 11 => 1 ],
        [ 2, 11 => -1 ],
        [ 3, 11 => 1 ],
        [ 4, 11 => 1 ],
        [ 5, 11 => 1 ],
        [ 6, 11 => -1 ],
        [ 7, 11 => -1 ],
        [ 8, 11 => -1 ],
        [ 9, 11 => 1 ],
        [ 10, 11 => -1 ],

        #Just random others
        [ 23, 478 => 1 ],
        [123123, 23423400 => 0],
        [470, 12071, => 1],
        [193136, 278103 => -1 ],
        [47000, 123123 => 1 ],
        [73564, 98741 => 1 ],
    );

    is( _count_lsb(8), 3, 'count LSB' );
    is( _count_lsb(3072), 10, 'count LSB 3072' );

    use Carp::Always;

    for my $tt (@t) {
        my $ret = _jacobi( map { Crypt::Perl::BigInt->new($_) } @{$tt}[0, 1] );
        is( $ret, $tt->[2], "@{$tt}[0,1] => $tt->[2]" );
    }

    return;
}

sub _bi { return Crypt::Perl::BigInt->new(@_) }

sub test_tonelli_shanks : Tests(9) {

    #cf. libtomcrypt demo/demo.c
    my @tests = (
        { n => 14, p => 5, r => 3 },    #or 2
        { n => 9, p => 7, r => 4 },     #or 3
        { n => 2, p => 113, r => 62 },  #or 51

        #https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
        { n => 10, p => 13, r => 6 },

        #https://rosettacode.org/wiki/Tonelli-Shanks_algorithm
        { n => 1030, p => 10009, r => 8377 },
        { n => 44402, p => 100049, r => 30468 },
        { n => 665820697, p => 1000000009, r => 621366697 },

        { n => _bi('881398088036'), p => _bi('1000000000039'), r => _bi('791399408049') },
        { n => _bi('41660815127637347468140745042827704103445750172002'), p => _bi('100000000000000000000000000000000000000000000000577'), r => _bi('67897014630059379150258016012699961096274733366069') },
    );

    for my $t (@tests) {
        is(
            _tonelli_shanks( @{$t}{ qw( n p ) } ),
            $t->{'r'},
            "N=$t->{'n'}, P=$t->{'p'}",
        );
    }

    return;
}

#cf. mp_sqrtmod_prime()
sub _tonelli_shanks {
    my ($n, $p) = @_;

    ref || ($_ = _bi($_)) for ($n, $p);

    return 0 if $n == 0;

    die sprintf( "jacobi(%s, %s) must not be -1", $n->as_hex(), $p->as_hex()) if _jacobi($n, $p) == -1;

    die "prime must be odd!" if $p == 2;

    if ( ($p % 4) == 3 ) {
        print "SPECIAL CASE----\n";
        return $n->copy()->bmodpow( $p->copy()->binc()->brsft(2), $p );
            #( ($n ** ( ($p+1) >> 2 )) % $p );
    }

    my $S = _bi(0);
    my $Q = $p - 1;
    while ( !($Q & 1) ) {
        $Q >>= 1;
        $S++;
    }
print "Q: [$Q] n/p [$n/$p]\n";

    my $Z = Crypt::Perl::BigInt->new(2);
    my $legendre;
print "while1-a\n";
    while (1) {
        last if _jacobi($Z, $p) == -1;
        $Z->binc();
    }
print "DONE\n";

    my $C = $Z->copy()->bmodpow($Q, $p);

    my $t1 = ($Q + 1) / 2;
die 'NaN' if ref($t1) && $t1->is_nan();
die 'NaN' if "$t1" eq "NaN";

    my $R = $n->copy()->bmodpow($t1, $p);

    my $T = $n->copy()->bmodpow($Q, $p);
print "T: [$T]\n";

    my $M = $S;

print "while1-b\n";
    while (1) {
        my $i = 0;
        $t1 = $T;

print "boo T=[$T]\n";
        while (1) {
print "t1: [$t1]\n";
#die 'NaN' if ref($t1) && $t1->is_nan();
#die 'NaN' if "$t1" eq "NaN";
            last if $t1 == 1;
            $t1->bmodpow(2, $p);
            $i++;
        }

        if ($i == 0) {
            return $R;
        }

#die 'NaN' if ref($t1) && $t1->is_nan();
#die 'NaN' if "$t1" eq "NaN";
print "power: [" . (($M - $i - 1) % $p) . "]\n";
        $t1 = _bi(2)->bmodpow($M - $i - 1, $p);
#die 'NaN' if ref($t1) && $t1->is_nan();
#die 'NaN' if "$t1" eq "NaN";

        $t1 = $C->bmodpow($t1, $p);
#die 'NaN' if ref($t1) && $t1->is_nan();
#die 'NaN' if "$t1" eq "NaN";

        $C = $t1->copy()->bmodpow(2, $p);
        $R->bmul($t1)->bmod($p);
        $T->bmul($C)->bmod($p);
        $M = _bi(1);
    }
}

#cf. mp_jacobi()
sub _jacobi {
    my ($a, $n) = @_;

    my $ret = 1;

    #This loop avoids deep recursion.
    while (1) {
        my ($ret2, $help) = _jacobi_backend($a, $n);
print "Jacobi A: $a\nJacobi N: $n\n";

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

sub _jacobi_backend {
    my ($a, $n) = @_;

#    print "Jacobi A: $a\n";
#    print "Jacobi N: $n\n";

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
print "k: [$k]\n";

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

#    my $r = _jacobi($p1, $a1);

#    return $s * $r;
}

#cf. mp_cnt_lsb()
sub _count_lsb {
    my ($num) = @_;

    #sprintf('%b',$num) =~ m<(0*)\z>;
    $num->as_bin() =~ m<(0*)\z>;

    return length $1;
}

sub test_seed : Tests(1) {
    my $pem = File::Slurp::read_file("$FindBin::Bin/assets/ecdsa_named_curve/secp112r1.key");
    my $key = Crypt::Perl::ECDSA::Parse::private($pem)->get_public_key();

    my $curve_data = Crypt::Perl::ECDSA::EC::DB::get_curve_data_by_name('secp112r1');
    my $seed_hex = substr( $curve_data->{'seed'}->as_hex(), 2 );

    my $der_hex = unpack 'H*', $key->to_der_with_explicit_curve();

    like( $der_hex, qr<\Q$seed_hex\E>, 'seed is in explicit parameters' );

    return;
}

#cf. RFC 7517, page 25
sub test_jwk : Tests(2) {
    my $prkey = Crypt::Perl::ECDSA::PublicKey->new_by_curve_name(
        Crypt::Perl::BigInt->from_bytes( "\x04" . MIME::Base64::decode_base64url('MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4') . MIME::Base64::decode_base64url('4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM') ),
        'prime256v1',
    );

    my $pub_jwk = $prkey->get_struct_for_public_jwk();

    my $expected_pub = {
        kty => "EC",
        crv => "P-256",
        x => "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        y => "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    };

    is_deeply(
        $pub_jwk,
        $expected_pub,
        'get_struct_for_public_jwk()',
    ) or diag explain $pub_jwk;

    #from Crypt::PK::ECC
    my $sha384_thumbprint = 'bLeg0iV0lOxemYi1inZct_fpBVGT0PjmOJfkLKNQzwiVJph-qr70kbtxqtdk9pVx';

    is(
        $prkey->get_jwk_thumbprint('sha384'),
        $sha384_thumbprint,
        'to_jwk_thumbprint(sha384)',
    );

    return;
}

sub test_subject_public_key : Tests(1) {
    my ($self) = @_;

    my $key_path = "$FindBin::Bin/assets/prime256v1.key.public";

    my $pem = File::Slurp::read_file($key_path);

    $pem = Crypt::Format::pem2der($pem);

    isa_ok(
        Crypt::Perl::ECDSA::Parse::public($pem),
        'Crypt::Perl::ECDSA::PublicKey',
        'public key parse',
    );

    return;
}

sub test_to_der_with_explicit_curve : Tests(1) {
    my $key_path = "$FindBin::Bin/assets/prime256v1_explicit.key.public";

    my $pkey_pem = File::Slurp::read_file($key_path);
    my $der1 = Crypt::Format::pem2der($pkey_pem);

    my $ecdsa = Crypt::Perl::ECDSA::Parse::public($pkey_pem);

    my $der2 = $ecdsa->to_der_with_explicit_curve();

    $_ = unpack('H*', $_) for $der2, $der1;

    is(
        $der2,
        $der1,
        'output DER matches the input',
    );

    return;
}

sub test_to_der_with_curve_name : Tests(1) {
    my $key_path = "$FindBin::Bin/assets/prime256v1.key.public";

    my $pkey_pem = File::Slurp::read_file($key_path);
    my $der1 = Crypt::Format::pem2der($pkey_pem);

    my $ecdsa = Crypt::Perl::ECDSA::Parse::public($pkey_pem);

    my $der2 = $ecdsa->to_der_with_curve_name();

    $_ = unpack('H*', $_) for $der2, $der1;

    is(
        $der2,
        $der1,
        'output DER matches the input',
    );

    return;
}

sub test_verify : Tests(2) {
    my ($self) = @_;

    my $key_path = "$FindBin::Bin/assets/prime256v1.key.public";

    my $pkey_pem = File::Slurp::read_file($key_path);

    my $ecdsa = Crypt::Perl::ECDSA::Parse::public($pkey_pem);

    my $msg = 'Hello';

    my $sig = pack 'H*', '3046022100e3d248766709081d22f1c2762a79ac1b5e99edc2fe147420e1131cb207859300022100ad218584c31c55b2a15d1598b00f425bfad41b3f3d6a4eec620cc64dfc931848';

    is(
        $ecdsa->verify( $msg, $sig ),
        1,
        'verify() - positive',
    );

    my $bad_sig = $sig;
    $bad_sig =~ s<.\z><9>;

    is(
        $ecdsa->verify( $msg, $bad_sig ),
        0,
        'verify() - negative',
    );

    return;
}

1;
