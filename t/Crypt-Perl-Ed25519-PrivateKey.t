package t::Crypt::Perl::Ed25519::PrivateKey;

use strict;
use warnings;

use Test::More;
use Test::Deep;

use Bytes::Random::Secure::Tiny ();

use FindBin;
use lib "$FindBin::Bin/../lib";

use Crypt::Perl::ED25519::PrivateKey;

my $msg = 'test';

my $key = Crypt::Perl::ED25519::PrivateKey->new('01234567890123456789012345678901');

my $signature = $key->sign($msg);

cmp_deeply(
    [ unpack 'C*', $signature ],
    [ 97,68,231,142,114,20,32,84,42,59,212,177,59,182,143,41,165,138,164,199,94,17,44,24,176,202,84,5,74,48,117,63,136,196,250,28,130,1,232,251,158,60,163,46,6,27,119,230,184,59,186,61,115,60,249,205,72,94,172,56,206,229,198,5 ],
    'signature of “test”',
#) or diag "got: @signature";
) or diag sprintf( "got: %v.02x", $signature );

is(
    $key->verify( $msg, $signature ),
    1,
    'verify()',
);

substr( $signature, 0, 1, 'z' );

ok(
    !$key->verify( $msg, $key->sign("$msg $msg") ),
    'verify() - mismatch',
);

#----------------------------------------------------------------------
my @priv1 = ( 226, 85, 30, 181, 147, 126, 178, 234, 14, 82, 163, 108, 30, 146, 174, 101, 160, 27, 188, 20, 189, 13, 91, 33, 156, 147, 170, 24, 41, 250, 191, 143 );

my @pub1 = ( 149, 76, 21, 14, 234, 81, 92, 79, 160, 82, 8, 246, 69, 114, 70, 202, 242, 205, 147, 62, 245, 189, 87, 25, 230, 4, 106, 16, 135, 62, 147, 164 );
my $pub_str = join q<.>, map { sprintf '%02x', $_ } @pub1;

my $key1 = Crypt::Perl::ED25519::PrivateKey->new( join q<>, map { chr } @priv1 );
is_deeply(
    sprintf('%v.02x', $key1->get_public() ),
    $pub_str,
    'correct public key determined',
);

my $msg1 = join q<>, map { chr hex } split m<\.>, "37.21.9a.9e.99.d9.53.47.cb.ca.3f.e9.48.11.3d.77.95.ff.a1.08.8f.72.21.89";

my $sig = $key1->sign($msg1);

my @sig_expected = ( 181, 101, 175, 84, 190, 112, 120, 163, 135, 130, 242, 246, 236, 211, 245, 38, 150, 170, 125, 135, 62, 201, 92, 224, 228, 214, 218, 91, 136, 7, 191, 220, 167, 79, 128, 48, 249, 179, 246, 144, 164, 48, 111, 14, 136, 89, 79, 230, 60, 106, 243, 75, 59, 193, 192, 13, 87, 97, 18, 73, 120, 209, 34, 10 );
my $sig_expected_str = join q<.>, map { sprintf '%02x', $_ } @sig_expected;

is(
    sprintf('%v.02x', $sig),
    $sig_expected_str,
    'expected signature',
);

#----------------------------------------------------------------------

my $rng = Bytes::Random::Secure::Tiny->new();

for my $i ( 1 .. 16 ) {
    my $key = Crypt::Perl::ED25519::PrivateKey->new();

    my $msg1 = $rng->bytes(24);
    my $sig1 = $key->sign($msg1);

    ok( $key->verify($msg1, $sig1), "round-trip ($i) - should match" ) or do {
        diag explain( {
            key => $key,
            message => sprintf('%v.02x', $msg1),
            signature => sprintf('%v.02x', $sig1),
        } );
    };

    my $msg2 = $rng->bytes(25);

    ok( !$key->verify($msg2, $sig1), "round-trip ($i) - should mismatch" ) or do {
        diag explain( {
            key => $key,
            message => sprintf('%v.02x', $msg2),
            signature => sprintf('%v.02x', $sig1),
        } );
    };
}

done_testing();


