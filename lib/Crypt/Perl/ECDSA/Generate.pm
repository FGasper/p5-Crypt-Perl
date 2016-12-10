package Crypt::Perl::ECDSA::Generate;

=encoding utf-8

=head1 NAME

Crypt::Perl::ECDSA::Generate - ECDSA key generation

=head1 SYNOPSIS

    use Crypt::Perl::ECDSA::Generate ();

    my $key = Crypt::Perl::ECDSA::Generate::by_name('secp521r1');

    my $signature = $key->sign('Hello!');

    die 'Wut' if $key->verify('Hello!', $signature);

=cut

use strict;
use warnings;

use Crypt::Perl::BigInt ();
use Crypt::Perl::Math ();
use Crypt::Perl::RNG ();
use Crypt::Perl::ECDSA::EC::DB ();
use Crypt::Perl::ECDSA::EC::Curve ();
use Crypt::Perl::ECDSA::PrivateKey ();

#The curve name is optional; if given, only the name will be encoded
#into the key rather than the explicit curve parameters.
sub by_name {
    my ($curve_name) = @_;

    my $key_parts = _generate(
        Crypt::Perl::ECDSA::EC::DB::get_curve_data_by_name($curve_name),
    );

    return Crypt::Perl::ECDSA::PrivateKey->new_by_curve_name($key_parts, $curve_name);
}

sub by_explicit_curve {
    my ($curve_hr) = @_;

    my $key_parts = _generate($curve_hr);

    return Crypt::Perl::ECDSA::PrivateKey->new($key_parts, $curve_hr);
}

#from generateKeyPairHex() in jsrsasign
sub _generate {
    my ($curve_hr) = @_;

    my $biN = $curve_hr->{'n'};

    my $biPrv = Crypt::Perl::Math::randint( $biN );

    #my $G = '04' . join(q<>, map { substr( $_->as_hex(), 2 ) } @{$curve}{'gx','gy'});
    #$G = Crypt::Perl::BigInt->from_hex($full_g);

    my $curve = Crypt::Perl::ECDSA::EC::Curve->new( @{$curve_hr}{'p', 'a', 'b'} );

    my $G = $curve->decode_point( @{$curve_hr}{'gx','gy'});

    my $epPub = $G->multiply($biPrv);
    my $biX = $epPub->get_x()->to_bigint();
    my $biY = $epPub->get_y()->to_bigint();

    my $key_hex_len = Crypt::Perl::Math::ceil( $curve->keylen() / 4 );

    my ($hx, $hy) = map { substr( $_->as_hex(), 2 ) } $biX, $biY;

    $_ = sprintf "%0${key_hex_len}s", $_ for ($hx, $hy);

    my $biPub = Crypt::Perl::BigInt->from_hex("04$hx$hy");

    return {
        version => 0,
        private => $biPrv,
        public => $biPub,
    };
}

#sub generate {
#    my ($curve_name) = @_
#
#    my $curve_hr = Crypt::Perl::ECDSA::EC::DB::get_curve_data_by_name($curve_name);
#
#    my $bytes = $curve_hr->{'n'}->as_hex() / 2 - 1;
#    my $ns2 = $curve_hr->{'n'} - 2;
#
#    do {
#        my $priv = _gen_bignum($bytes);
#        next if $priv > $ns2;
#
#        $priv += 1;
#
#        return _key_from_private($curve_hr, $priv);
#    } while 1;
#}
#
#sub _key_from_private {
#    return _keypair( $curve_hr, $priv );
#}
#
#sub _keypair {
#    my ($curve_hr, $priv) = @_;
#
#    $priv %= $curve_hr->{'n'};
#
#    my $full_g = '04' . join(q<>, map { substr( $_->as_hex(), 2 ) } @{$curve}{'gx','gy'});
#    $full_g = Crypt::Perl::BigInt->from_hex($full_g);
#
#    return {
#        priv => $priv,
#        pub => $full_g * $priv,
#    };
#}
#
#sub _gen_bignum {
#    my ($bits) = @_;
#
#    return Crypt::Perl::BigInt->from_bin( Crypt::Perl::RNG::bit_string($bits) );
#}

1;
