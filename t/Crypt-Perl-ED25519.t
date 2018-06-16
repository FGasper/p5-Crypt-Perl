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

my @signature = Crypt::Perl::ED25519::sign(
    $priv_pub[0],
    $priv_pub[1],
    'test',
);

cmp_deeply(
    \@signature,
    [ 97,68,231,142,114,20,32,84,42,59,212,177,59,182,143,41,165,138,164,199,94,17,44,24,176,202,84,5,74,48,117,63,136,196,250,28,130,1,232,251,158,60,163,46,6,27,119,230,184,59,186,61,115,60,249,205,72,94,172,56,206,229,198,5 ],
    'signature of “test”',
) or diag "got: @signature";

done_testing();

__END__

> ./apps/openssl genpkey -algorithm Ed25519 | ./apps/openssl pkey -pubout
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApBd35anoujAfA6FhdrV0znBJK92cFJL4HSGJ9m8XvUA=
-----END PUBLIC KEY-----

OK
felipe@Felipes-MacBook-Pro 10:36:47 ~/temp/openssl-1.1.1-pre7
> pbpaste | openssl asn1parse -i
    0:d=0  hl=2 l=  42 cons: SEQUENCE          
    2:d=1  hl=2 l=   5 cons:  SEQUENCE          
    4:d=2  hl=2 l=   3 prim:   OBJECT            :1.3.101.112
    9:d=1  hl=2 l=  33 prim:  BIT STRING 


> ./apps/openssl genpkey -algorithm Ed25519
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEvpzPoCvfFonFL4jqMsSdpC76qg9E0mwtJPdQsOlEbx
-----END PRIVATE KEY-----

OK
felipe@Felipes-MacBook-Pro 10:37:14 ~/temp/openssl-1.1.1-pre7
> pbpaste | openssl asn1parse -i
    0:d=0  hl=2 l=  46 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim:  INTEGER           :00
    5:d=1  hl=2 l=   5 cons:  SEQUENCE          
    7:d=2  hl=2 l=   3 prim:   OBJECT            :1.3.101.112
   12:d=1  hl=2 l=  34 prim:  OCTET STRING      [HEX DUMP]:04204BE9CCFA02BDF1689C52F88EA32C49DA42EFAAA0F44D26C2D24F750B0E9446F1
