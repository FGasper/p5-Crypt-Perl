package Crypt::Perl::ED25519::PrivateKey;

use strict;
use warnings;

use parent qw(
  Crypt::Perl::ED25519::KeyBase
);

use Digest::SHA ();

use Crypt::Perl::ED25519::Math;

sub new {
    my ($class, $priv, $pub) = @_;

    $priv ||= do {
        require Crypt::Perl::RNG;
        Crypt::Perl::RNG::bytes(32);
    };

    $pub ||= _deduce_public_from_private($priv);

    return bless {
        _public => $pub,
        _public_ar => [ unpack 'C*', $pub ],
        _private => $priv,
        _private_ar => [ unpack 'C*', $priv ],
    }, $class;
}

sub get_public_key {
    my ($self) = @_;

    return Crypt::Perl::ED25519::PublicKey->new( $self->{'_public'} );
}

sub sign {
    my ($self, $msg) = @_;

    my @x = (0) x 64;

    my @p = map { [ Crypt::Perl::ED25519::Math::gf0() ] } 1 .. 4;

    my $digest_ar = _digest32( $self->{'_private'} );

    my @sm = (0) x 32;
    push @sm, @{$digest_ar}[32 .. 63];
    push @sm, unpack( 'C*', $msg );

    my @r = unpack 'C*', Digest::SHA::sha512( pack 'C*', @sm[32 .. $#sm] );
use Data::Dumper;
    Crypt::Perl::ED25519::Math::reduce(\@r);
#print STDERR Dumper( 'after reduce', "@r" );
    Crypt::Perl::ED25519::Math::scalarbase( \@p, \@r );
#print STDERR Dumper( 'after scalarbase', \@p, \@r );
    @sm[ 0 .. 31 ] = @{ Crypt::Perl::ED25519::Math::pack(\@p) };

    @sm[32 .. 63] = @{$self->{'_public_ar'}};

    my @h = unpack 'C*', Digest::SHA::sha512( pack 'C*', @sm );
    Crypt::Perl::ED25519::Math::reduce( \@h );

    @x[0 .. 31] = @r[0 .. 31];

    for my $i ( 0 .. 31) {
        for my $j ( 0 .. 31 ) {
            $x[ $i + $j ] += $h[$i] * $digest_ar->[$j];
        }
    }

    my @latter_sm = @sm[32 .. $#sm];

    Crypt::Perl::ED25519::Math::modL( \@latter_sm, \@x );

    @sm[32 .. $#sm] = @latter_sm;

    return pack 'C*', @sm[ 0 .. ($self->SIGN_BYTE_LENGTH - 1) ];
}

#----------------------------------------------------------------------

sub _deduce_public_from_private {
    my ($private) = @_;

    my $digest_ar = _digest32($private);

    my $p = [ map { [ Crypt::Perl::ED25519::Math::gf0() ] } 0 .. 3 ];

    # private key is 32 bytes for private part
    # plus 32 bytes for the public part

    Crypt::Perl::ED25519::Math::scalarbase($p, $digest_ar);
    my $pk = Crypt::Perl::ED25519::Math::pack($p);

    return pack 'C*', @$pk;
}

sub _digest32 {
    my ($seed) = @_;

    my @digest = unpack 'C*', Digest::SHA::sha512($seed);
    $digest[0]  &= 0xf8;    #248
    $digest[31] &= 0x7f;    #127
    $digest[31] |= 0x40;    # 64

    return \@digest;
}

1;
