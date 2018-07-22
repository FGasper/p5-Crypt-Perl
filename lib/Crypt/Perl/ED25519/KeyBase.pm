package Crypt::Perl::ED25519::KeyBase;

use strict;
use warnings;

use Crypt::Perl::ED25519::Math;

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
    #my @t = (0) x 32;
    @m = @sm;

    @m[ 32 .. 63 ] = @{$public_ar};
#print "M:: @m\n";
#print "SM: @sm\n";

    my @p = map { [ Crypt::Perl::ED25519::Math::gf0() ] } 1 .. 4;
    my @q = map { [ Crypt::Perl::ED25519::Math::gf0() ] } 1 .. 4;

    if ( Crypt::Perl::ED25519::Math::unpackneg( \@q, $public_ar ) ) {
        #die "-1??";
        return !1;
    }

use Data::Dumper;
#print STDERR Dumper( q_after_unpackneg => \@q );
#print STDERR Dumper( 0 + @m, m => \@m );

    my @h = unpack 'C*', Digest::SHA::sha512( pack 'C*', @m );
#print STDERR Dumper( 0 + @h, h => \@h );
    Crypt::Perl::ED25519::Math::reduce(\@h);

#print STDERR Dumper(before_scalarmult => \@p, \@q, \@h);
    Crypt::Perl::ED25519::Math::scalarmult(\@p, \@q, \@h);
#print STDERR Dumper(p_after_scalarmult => \@p);

    my @latter_sm = @sm[32 .. $#sm];
    Crypt::Perl::ED25519::Math::scalarbase( \@q, \@latter_sm );
    @sm[32 .. $#sm] = @latter_sm;

    Crypt::Perl::ED25519::Math::add( \@p, \@q );
    my $t_ar = Crypt::Perl::ED25519::Math::pack(\@p);

    my $n = @sm - SIGN_BYTE_LENGTH;

use Data::Dumper;
#print STDERR Dumper( sm => \@sm, t => $t_ar );
    if( Crypt::Perl::ED25519::Math::crypto_verify_32(\@sm, 0, $t_ar, 0)) {
        #$_ = 0 for @m[0 .. ($n - 1)];
        #return -1;
        #die "-1?? (b)";
        return !1;
    }

    return $n >= 0;
    #for my $i ( 0 .. $n ) {
        
#  for(i = 0; i < n; ++i) {
#    m[i] = sm[i + 64];
#  }
#  mlen = n;
#return mlen;
}

1;
