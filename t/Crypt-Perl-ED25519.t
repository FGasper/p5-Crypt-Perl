package t::Crypt::Perl::ED25519;

use strict;
use warnings;

use Test::More;
use Test::Deep;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Crypt::Perl::ED25519;

my @priv_pub = Crypt::Perl::ED25519::generate_key_pair(
    seed => '01234567890123456789012345678901',
);

cmp_deeply(
    \@priv_pub,
    [
        [ 48,49,50,51,52,53,54,55,56,57,48,49,50,51,52,53,54,55,56,57,48,49,50,51,52,53,54,55,56,57,48,49 ],
        [ 123,195,7,149,24,237,17,218,3,54,8,91,246,150,41,32,255,135,251,60,77,99,10,155,88,203,97,83,103,79,93,214 ],
    ],
    'private (seeded) and public key parts',
) or diag explain \@priv_pub;

done_testing();
