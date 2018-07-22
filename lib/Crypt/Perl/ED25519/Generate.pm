package Crypt::Perl::ED25519::Generate;

=encoding utf-8

=cut

use constant SEED_BYTE_LENGTH => 32;

sub generate {
    my ($private) = @_;

    if ($private) {
        if (SEED_BYTE_LENGTH != length $private) {
            die sprintf("Seed (%v.02x) is not %d bytes!", $private, SEED_BYTE_LENGTH());
        }
    }
    else {
        require Crypt::Perl::RNG;
        $private = Crypt::Perl::RNG::bytes( SEED_BYTE_LENGTH() );
    }

    # crypto_sign_keypair

    my @digest = _digest32($private);

    my $p = [ map { [ gf0() ] } 0 .. 3 ];

    # private key is 32 bytes for private part
    # plus 32 bytes for the public part

    _scalarbase($p, \@digest);
    my $pk = _pack($p);

    return __PACKAGE__->new( 
}

1;
