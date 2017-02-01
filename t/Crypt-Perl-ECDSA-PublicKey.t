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
#    my $x = '4568afff28d7bec0a5d2919f349fea579c9ae36740bbc2dc671418f3fab5e412';
#    my $a = 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc';
#    my $b = '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b';
#    my $p = 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff';
#----------------------------------------------------------------------

    my $p = 'fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d';
    my $a = '00';
    my $b = '05';
    my $x = '2bc04ac1bd74c1f27ce7d5e78aa8f71935a67f06245eaf932c26ca2e';

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
    $y = Crypt::Perl::ECDSA::Math::tonelli_shanks( $y, $p );

    if (!!$y_is_even eq !!$y->is_odd()) {
        $y->bsub($p)->bneg();
    }

#    if (!!$y_is_even eq !!$y->is_even()) {
#        $y = $t2->bmod($p);
#    }
#    else {
#        $y = ($p - $t2);
#        $y->bmod($p);
#    }

    print $y->as_hex() . $/;

    return;
}

sub test_seed : Tests(1) {
    my $pem = File::Slurp::read_file("$FindBin::Bin/assets/ecdsa_named_curve_compressed/secp112r1.key");
use Carp::Always;
    my $key = Crypt::Perl::ECDSA::Parse::private($pem)->get_public_key();

    my $curve_data = Crypt::Perl::ECDSA::EC::DB::get_curve_data_by_name('secp112r1');
    my $seed_hex = substr( $curve_data->{'seed'}->as_hex(), 2 );

    my $der_hex = unpack 'H*', $key->to_der_with_explicit_curve();

    like( $der_hex, qr<\Q$seed_hex\E>, 'seed is in explicit parameters' );

    return;
}

#cf. RFC 7517, page 25
sub test_jwk : Tests(2) {
    my $pbkey = Crypt::Perl::ECDSA::PublicKey->new_by_curve_name(
        Crypt::Perl::BigInt->from_bytes( "\x04" . MIME::Base64::decode_base64url('MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4') . MIME::Base64::decode_base64url('4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM') ),
        'prime256v1',
    );

    my $pub_jwk = $pbkey->get_struct_for_public_jwk();

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
        $pbkey->get_jwk_thumbprint('sha384'),
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
