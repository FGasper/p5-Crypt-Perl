package Crypt::Perl::PK;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Crypt::Perl::PK - Public-key cryptography logic

=head1 SYNOPSIS

    #Will be an instance of the appropriate Crypt::Perl key class,
    #i.e., one of:
    #
    #   Crypt::Perl::RSA::PrivateKey
    #   Crypt::Perl::RSA::PublicKey
    #   Crypt::Perl::ECDSA::PrivateKey
    #   Crypt::Perl::ECDSA::PublicKey
    #
    my $key_obj = Crypt::Perl::PK::parse_jwk( { .. } );

=head1 DISCUSSION

As of now there’s not much of interest to find here except
parsing of L<JWK|https://tools.ietf.org/html/rfc7517>s.

=cut

use Module::Load ();

use Crypt::Perl::X ();

sub parse_jwk {
    my ($hr) = @_;

    if ('HASH' ne ref $hr) {
        die Crypt::Perl::X::create('InvalidJWK', $hr);
    }

    my $kty = $hr->{'kty'};

    if ($kty) {
        my $module;

        if ($kty eq 'RSA') {
            $module = 'Crypt::Perl::RSA::Parse';

        }
        elsif ($kty eq 'EC') {
            $module = 'Crypt::Perl::ECDSA::Parse';
        }
        else {
            die Crypt::Perl::X::create('UnknownJTKkty', $kty);
        }

        Module::Load::load($module);

        return $module->can('jwk')->($hr);
    }

    die Crypt::Perl::X::create('InvalidJWK', %$hr);
}

1;
