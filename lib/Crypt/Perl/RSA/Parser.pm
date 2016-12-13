package Crypt::Perl::RSA::Parser;

=encoding utf-8

=head1 NAME

Crypt::Perl::RSA::Parser - RSA key parsing

=head1 SYNOPSIS

    use Crypt::Perl::RSA::Parser ();

    #These accept either DER or PEM, native format or PKCS8.
    #
    my $prkey = Crypt::Perl::RSA::Parser::private($buffer);
    my $pbkey = Crypt::Perl::RSA::Parser::public($buffer);

=cut

use strict;
use warnings;

use Try::Tiny;

use Crypt::Format ();

use Crypt::Perl::ASN1 ();
use Crypt::Perl::Load ();
use Crypt::Perl::RSA::Template ();

sub _asn1 {
    return Crypt::Perl::ASN1->new()->prepare(
        Crypt::Perl::RSA::Template::get_template('INTEGER'),
    );
}

sub private {
    my ( $pem_or_der) = @_;

    _ensure_der($pem_or_der);

    my $key_obj;

    try {
        my $parsed = _decode_rsa($pem_or_der);
        $key_obj = _new_private($parsed);
    }
    catch {
        my $rsa_err = $_;

        try {
            my $pkcs8 = _decode_pkcs8($pem_or_der);
            $key_obj = _decode_rsa_within_pkcs8_or_die($pkcs8);
        }
        catch {
            die "Failed to parse as either RSA ($rsa_err) or PKCS8 ($_)";
        };
    };

    return $key_obj;
}

#Like private(), but only does PKCS8.
sub private_pkcs8 {
    my ($pem_or_der) = @_;

    _ensure_der($pem_or_der);

    my $pkcs8 = _decode_pkcs8($pem_or_der);

    my $parsed = _decode_rsa_within_pkcs8_or_die($pkcs8);

    return _new_private($parsed);
}

#Checks for RSA format first, then falls back to PKCS8.
sub public {
    my ($pem_or_der) = @_;

    _ensure_der($pem_or_der);

    my $key_obj;

    try {
        my $parsed = _decode_rsa_public($pem_or_der);
        $key_obj = _new_public($parsed);
    }
    catch {
        my $rsa_err = $_;

        try {
            my $pkcs8 = _decode_pkcs8_public($pem_or_der);
            $key_obj = _decode_rsa_public_within_pkcs8_or_die($pkcs8);
        }
        catch {
            die "Failed to parse as either RSA ($rsa_err) or PKCS8 ($_)";
        };
    };

    return $key_obj;
}

#Like public(), but only does PKCS8.
sub public_pkcs8 {
    my ($pem_or_der) = @_;

    _ensure_der($pem_or_der);

    my $pkcs8 = _decode_pkcs8_public($pem_or_der);

    my $parsed = _decode_rsa_public_within_pkcs8_or_die($pkcs8);

    return _new_public($parsed);
}

sub _decode_macro {
    my ( $der_r, $macro ) = ( \$_[0], $_[1] );

    my $parser = _asn1()->find($macro);

    return $parser->decode($$der_r);
}

#Checks for RSA format first, then falls back to PKCS8.
sub _decode_rsa {
    my ($der_r) = (\$_[0]);

    return _decode_macro( $$der_r, 'RSAPrivateKey' );
}

sub _decode_rsa_public {
    my ($der_r) = (\$_[0]);

    return _decode_macro( $$der_r, 'RSAPublicKey' );
}

sub _decode_rsa_within_pkcs8_or_die {
    my ($pkcs8_hr) = @_;

    my $dec;
    try {
        $dec = _decode_rsa( $pkcs8_hr->{'privateKey'} );
    }
    catch {
        die "Failed to parse RSA within PKCS8: $_";
    };

    return $dec;
}

sub _decode_rsa_public_within_pkcs8_or_die {
    my ($pkcs8_hr) = @_;

    my $dec;
    try {
        $dec = _decode_rsa_public( $pkcs8_hr->{'subjectPublicKey'}[0] );
    }
    catch {
        die "Failed to parse RSA within PKCS8: $_";
    };

    return $dec;
}

sub _decode_pkcs8 {
    my ($der_r) = (\$_[0]);

    return _decode_macro( $$der_r, 'PrivateKeyInfo' );
}

sub _decode_pkcs8_public {
    my ($der_r) = (\$_[0]);

    return _decode_macro( $$der_r, 'SubjectPublicKeyInfo' );
}

sub _new_public {
    my ($parsed_hr) = @_;

    Crypt::Perl::Load::module('Crypt::Perl::RSA::PublicKey');
    return Crypt::Perl::RSA::PublicKey->new($parsed_hr);
}

sub _new_private {
    my ($parsed_hr) = @_;

    Crypt::Perl::Load::module('Crypt::Perl::RSA::PrivateKey');
    return Crypt::Perl::RSA::PrivateKey->new($parsed_hr);
}

#Modifies in-place.
sub _pem_to_der {
    $_[0] = Crypt::Format::pem2der(@_);

    return;
}

sub _ensure_der {
    my ($pem_or_der_r) = \$_[0];

    if ( $$pem_or_der_r =~ m<\A-> ) {
        _pem_to_der($$pem_or_der_r);
    }

    return;
}

1;
