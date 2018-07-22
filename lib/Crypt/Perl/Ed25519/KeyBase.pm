package Crypt::Perl::Ed25519::KeyBase;

use strict;
use warnings;

use Crypt::Perl::Ed25519::Math;

use Digest::SHA ();

use constant SIGN_BYTE_LENGTH => 64;

sub get_public {
    my ($self) = @_;

    return $self->{'_public'};
}

sub verify {
    my ($self, $msg, $sig) = @_;

    my $public_ar = $self->{'_public_ar'};

    my $sig_ar = [ unpack 'C*', $sig ];

    my @sm = ( @$sig_ar, unpack( 'C*', $msg ) );
    my @m = (0) x @sm;

    @m = @sm;

    @m[ 32 .. 63 ] = @{$public_ar};

    my @p = map { [ Crypt::Perl::Ed25519::Math::gf0() ] } 1 .. 4;
    my @q = map { [ Crypt::Perl::Ed25519::Math::gf0() ] } 1 .. 4;

    if ( Crypt::Perl::Ed25519::Math::unpackneg( \@q, $public_ar ) ) {
        return !1;
    }

    my @h = unpack 'C*', Digest::SHA::sha512( pack 'C*', @m );
    Crypt::Perl::Ed25519::Math::reduce(\@h);

    Crypt::Perl::Ed25519::Math::scalarmult(\@p, \@q, \@h);

    my @latter_sm = @sm[32 .. $#sm];
    Crypt::Perl::Ed25519::Math::scalarbase( \@q, \@latter_sm );
    @sm[32 .. $#sm] = @latter_sm;

    Crypt::Perl::Ed25519::Math::add( \@p, \@q );
    my $t_ar = Crypt::Perl::Ed25519::Math::pack(\@p);

    if( Crypt::Perl::Ed25519::Math::crypto_verify_32(\@sm, 0, $t_ar, 0)) {
        return !1;
    }

    my $n = @sm - SIGN_BYTE_LENGTH;

    return $n >= 0;
}

1;
