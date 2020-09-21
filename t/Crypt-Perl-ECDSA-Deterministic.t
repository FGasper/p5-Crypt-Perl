package t::Crypt::Perl::PK;

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
use Test::FailWarnings;
use Test::Deep;
use Test::Exception;

use lib "$FindBin::Bin/lib";

use parent qw(
    TestClass
);

use Digest::SHA ();
use Crypt::Perl::ECDSA::EC::DB ();
use Crypt::Perl::BigInt ();

use Crypt::Perl::ECDSA::Deterministic ();

__PACKAGE__->new()->runtests() if !caller;

#----------------------------------------------------------------------

use constant _SAMPLE_TESTS => (
    {
        label => 'detailed example from RFC',
        order => '4000000000000000000020108A2E0CC0D99F8A5EF',
        key => '09A4D6792295A7F730FC3F2B49CBC0F62E862272F',
        hash => 'sha256',
        expect => '23af4074c90a02b3fe61d286d5c87f425e6bdd81b',
    },

    {
        label => 'python-ecdsa, SECP256k1 (1)',
        order => 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
        key => '9d0219792467d7d37b4d43298a7d0c05',
        hash => 'sha256',
        expect => '8fa1f95d514760e498f28957b824ee6ec39ed64826ff4fecc2b5739ec45b91cd',
    },

    {
        label => 'python-ecdsa, SECP256k1 (2)',
        order => 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
        key => 'cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50',
        hash => 'sha256',
        expect => '2df40ca70e639d89528a6b670d9d48d9165fdc0febc0974056bdce192b8e16a3',
    },

    (
        map {
            my ($hashfn, $expect) = @$_;

            {
                label => "P-192, $hashfn",
                order => 'FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831',
                key => '6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4',
                hash => $hashfn,
                expect => $expect,
            },
        }
        [ sha1 => '37d7ca00d2c7b0e5e412ac03bd44ba837fdd5b28cd3b0021' ],
        [ sha224 => '4381526b3fc1e7128f202e194505592f01d5ff4c5af015d8' ],
        [ sha256 => '32b1b6d7d42a05cb449065727a84804fb1a3e34d8f261496' ],
        [ sha384 => '4730005c4fcb01834c063a7b6760096dbe284b8252ef4311' ],
        [ sha512 => 'a2ac7ab055e4f20692d49209544c203a7d1f2c0bfbc75db1' ],
    ),
);

sub new {
    my $self = shift()->SUPER::new(@_);

    $self->num_method_tests( 'test__generate_k__sample', 0 + @{ [ _SAMPLE_TESTS ] } );

    return $self;
}


sub test__generate_k__sample : Tests() {
    my $msg = 'sample';

    for my $t ( _SAMPLE_TESTS ) {
        my ($q, $key, $hashfn, $expect) = @{$t}{'order', 'key', 'hash', 'expect'};

        $_ = Crypt::Perl::BigInt->from_hex($_) for ($q, $key);
        my $hash_cr = Digest::SHA->can($hashfn);

        my $k = Crypt::Perl::ECDSA::Deterministic::generate_k($q, $key, $hash_cr, $msg);
        is(
            $k->to_hex(),
            $expect,
            $t->{label},
        );
    }

    return;
}

1;
