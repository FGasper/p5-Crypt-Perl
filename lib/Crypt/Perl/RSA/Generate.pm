package Crypt::Perl::RSA::Generate;

use strict;
use warnings;

use Math::ProvablePrime ();

use Crypt::Perl::BigInt ();
use Crypt::Perl::RNG ();
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
            #$p = Crypt::Perl::RSA::Math::create_random_bit_length($mod_bits - $qs);
            $p = Math::ProvablePrime::find($mod_bits - $qs);
            last;
            #next if ($p - 1)->bgcd($exp) != 1;
            #last if Crypt::Perl::RSA::Math::is_probable_prime($p, 10);
        }

        while (1) {
            #$q = Crypt::Perl::RSA::Math::create_random_bit_length($qs);
            $q = Math::ProvablePrime::find($qs);
            last;
            #if ( ($q - 1)-bgcd($exp) == 1 && Crypt::Perl::RSA::Math::is_probable_prime($q, 10) ) {
            #    last;
            #}
        }

        #$p should be at least as much as $q
        if ($p < $q) {
            my $t = $p;
            $p = $q;
            $q = $t;
        }

        my $qinv = $q->copy()->bmodinv($p);

        #This isn’t in the original algorithm. It may only be necessary here
        #because of the incomplete is_probable_prime() implementation.
        next if $qinv->is_nan();

        my $p1 = $p - 1;
        my $q1 = $q - 1;
        my $phi = $p1 * $q1;

        if ($phi->bgcd($exp) == 1) {
            my $d = $exp->copy()->bmodinv($phi);

            my $obj = Crypt::Perl::RSA::PrivateKey->new(
                {
                    version => 0,
                    modulus => $p * $q,
                    publicExponent => $exp,
                    privateExponent => $d,
                    prime1 => $p,
                    prime2 => $q,
                    exponent1 => $d % $p1,
                    exponent2 => $d % $q1,
                    coefficient => $qinv,

#----------------------------------------------------------------------
#modulus => Crypt::Perl::BigInt->from_hex('00bf4ad360122e1d85a8da1aadbceff3a58a2a627f06d33b9bde76fede9dcd1454dc00c446f6116af57f60ae8f759a73d7'),
#publicExponent => 65537,
#privateExponent => Crypt::Perl::BigInt->from_hex('4d63e6544dc69e66fec30e5c0fbe3c2252dd86efc1412031e2225cf5a33c7b3db79635d6f93915fe4e5db061f24b4191'),
#prime1 => Crypt::Perl::BigInt->from_hex('00e0182280ae017f0f5dc331397272b758136424cf2b3e943b'),
#prime2 => Crypt::Perl::BigInt->from_hex('00da871cdd3adf9f723a499262824973fe164458c878bb3115'),
#exponent1 => Crypt::Perl::BigInt->from_hex('00d0ec2f5ea0dbac45fb387bafff4f8c3784fc9c84b8e082f9'),
#exponent2 => Crypt::Perl::BigInt->from_hex('00bf10c57ef4dbd31857b83e025d7205b5d2183e1c41db41a5'),
#coefficient => Crypt::Perl::BigInt->from_hex('00b193714c1e6ab6825722f537c6a4bf5736a588d259cf05b1'),
                },
            );

use Data::Dumper;
#print STDERR Dumper $obj;
            return $obj;
        }
    }
}

*_get_random_prime = \&Math::ProvablePrime::find;

1;

__DATA__
-----BEGIN RSA PRIVATE KEY-----
MIH0AgEAAjEAv0rTYBIuHYWo2hqtvO/zpYoqYn8G0zub3nb+3p3NFFTcAMRG9hFq
9X9gro91mnPXAgMBAAECME1j5lRNxp5m/sMOXA++PCJS3YbvwUEgMeIiXPWjPHs9
t5Y11vk5Ff5OXbBh8ktBkQIZAOAYIoCuAX8PXcMxOXJyt1gTZCTPKz6UOwIZANqH
HN06359yOkmSYoJJc/4WRFjIeLsxFQIZANDsL16g26xF+zh7r/9PjDeE/JyEuOCC
+QIZAL8QxX7029MYV7g+Al1yBbXSGD4cQdtBpQIZALGTcUwearaCVyL1N8akv1c2
pYjSWc8FsQ==
-----END RSA PRIVATE KEY-----

From OpenSSL:
3081f4020100023100bf4ad360122e1d85a8da1aadbceff3a58a2a627f06d33b9bde76fede9dcd1454dc00c446f6116af57f60ae8f759a73d7020301000102304d63e6544dc69e66fec30e5c0fbe3c2252dd86efc1412031e2225cf5a33c7b3db79635d6f93915fe4e5db061f24b4191021900e0182280ae017f0f5dc331397272b758136424cf2b3e943b021900da871cdd3adf9f723a499262824973fe164458c878bb3115021900d0ec2f5ea0dbac45fb387bafff4f8c3784fc9c84b8e082f9021900bf10c57ef4dbd31857b83e025d7205b5d2183e1c41db41a5021900b193714c1e6ab6825722f537c6a4bf5736a588d259cf05b1
