package Crypt::Perl::RSA::Generate;

=encoding utf-8

=head1 NAME

Crypt::Perl::RSA::Generate - RSA key generation

=head1 SYNOPSIS

    use Crypt::Perl::RSA::Generate ();

    #$prkey is a Crypt::Perl::RSA::PrivateKey instance.
    my $prkey = Crypt::Perl::RSA::Generate::create(2048);

=head1 DISCUSSION

Unfortunately, this is quite slow in Perl—too slow, in fact, if you
don’t have either L<Math::BigInt::GMP> or L<Math::BigInt::Pari>.

The current L<Math::ProvablePrime> backend is slated to be replaced
with L<Math::Prime::Util>; once that happens, pure-Perl operation should
be much more feasible.

=head1 ALTERNATIVES

=over 4

=item L<Crypt::OpenSSL::RSA>

=item Use the C<openssl> binary L<OpenSSL|http://openssl.org> directly.

=back

=cut

use strict;
use warnings;

use Math::ProvablePrime ();

use Crypt::Perl::BigInt ();
use Crypt::Perl::RSA::PrivateKey ();

use constant PUBLIC_EXPONENTS => ( 65537, 3 );

sub create {
    my ($mod_bits, $exp) = @_;

    die "Need modulus length!" if !$mod_bits;

    $exp ||= (PUBLIC_EXPONENTS())[0];

    if (!grep { $exp eq $_ } PUBLIC_EXPONENTS()) {
        my @allowed = PUBLIC_EXPONENTS();
        die "Invalid public exponent ($exp); should be one of: [@allowed]";
    }

    my $qs = $mod_bits >> 1;
    (ref $exp) or $exp = Crypt::Perl::BigInt->new($exp);

    while (1) {
        my ($p, $q);

        #Create a random number, ($mod_bits - $qs) bits long.
        while (1) {
            $p = _get_random_prime($mod_bits - $qs);
            last;
        }

        while (1) {
            $q = _get_random_prime($qs);
            last;
        }

        #$p should be at least as much as $q
        if ($p < $q) {
            my $t = $p;
            $p = $q;
            $q = $t;
        }

        my $qinv = $q->copy()->bmodinv($p);

        #This isn’t in the original algorithm. It may only have been needed
        #here with the old incomplete is_probable_prime() implementation.
        #It’s probably not necessary anymore, but it doesn’t hurt anything.
        next if $qinv->is_nan();

        my $p1 = $p->copy()->bdec();
        my $q1 = $q->copy()->bdec();
        my $phi = $p1->copy()->bmul($q1);

        if ($phi->bgcd($exp)->is_one()) {
            my $d = $exp->copy()->bmodinv($phi);

            my $obj = Crypt::Perl::RSA::PrivateKey->new(
                {
                    version => 0,
                    modulus => $p->copy()->bmul($q),
                    publicExponent => $exp,
                    privateExponent => $d,
                    prime1 => $p,
                    prime2 => $q,
                    exponent1 => $d->copy()->bmod($p1),
                    exponent2 => $d->copy()->bmod($q1),
                    coefficient => $qinv,
                },
            );

            return $obj;
        }
    }
}

*_get_random_prime = \&Math::ProvablePrime::find;

1;
