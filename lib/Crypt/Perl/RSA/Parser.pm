package Crypt::Perl::RSA::Parser;

use strict;
use warnings;

use Try::Tiny;

use Crypt::Format ();

use Crypt::Perl::ASN1 ();
use Crypt::Perl::Load ();
use Crypt::Perl::RSA::Template ();

sub new {
    my ($class) = @_;

    my $asn1 = Crypt::Perl::ASN1->new()->prepare(
        Crypt::Perl::RSA::Template::get_template('INTEGER'),
    );

    return bless { _asn1 => $asn1 }, $class;
}

sub _decode_macro {
    my ( $self, $der_r, $macro ) = ( shift, \$_[0], $_[1] );

    my $parser = $self->{'_asn1'}->find($macro);

    return $parser->decode($$der_r);
}

sub private {
    my ($self, $pem_or_der) = @_;

    _ensure_der($pem_or_der);

    my $key_obj;

    try {
        my $parsed = $self->_decode_rsa($pem_or_der);
        $key_obj = $self->_new_private($parsed);
    }
    catch {
        my $rsa_err = $_;

        try {
            my $pkcs8 = $self->_decode_pkcs8($pem_or_der);
            $key_obj = $self->_decode_rsa_within_pkcs8_or_die($pkcs8);
        }
        catch {
            die "Failed to parse as either RSA ($rsa_err) or PKCS8 ($_)";
        };
    };

    return $key_obj;
}

#Like private(), but only does PKCS8.
sub private_pkcs8 {
    my ($self, $pem_or_der) = @_;

    _ensure_der($pem_or_der);

    my $pkcs8 = $self->_decode_pkcs8($pem_or_der);

    my $parsed = $self->_decode_rsa_within_pkcs8_or_die($pkcs8);

    return $self->_new_private($parsed);
}

#Checks for RSA format first, then falls back to PKCS8.
sub public {
    my ($self, $pem_or_der) = @_;

    _ensure_der($pem_or_der);

    my $key_obj;

    try {
        my $parsed = $self->_decode_rsa_public($pem_or_der);
        $key_obj = $self->_new_public($parsed);
    }
    catch {
        my $rsa_err = $_;

        try {
            my $pkcs8 = $self->_decode_pkcs8_public($pem_or_der);
            $key_obj = $self->_decode_rsa_public_within_pkcs8_or_die($pkcs8);
        }
        catch {
            die "Failed to parse as either RSA ($rsa_err) or PKCS8 ($_)";
        };
    };

    return $key_obj;
}

#Like public(), but only does PKCS8.
sub public_pkcs8 {
    my ($self, $pem_or_der) = @_;

    _ensure_der($pem_or_der);

    my $pkcs8 = $self->_decode_pkcs8_public($pem_or_der);

    my $parsed = $self->_decode_rsa_public_within_pkcs8_or_die($pkcs8);

    return $self->_new_public($parsed);
}

#Checks for RSA format first, then falls back to PKCS8.
sub _decode_rsa {
    my ($self, $der_r) = (shift, \$_[0]);

    return $self->_decode_macro( $$der_r, 'RSAPrivateKey' );
}

sub _decode_rsa_public {
    my ($self, $der_r) = (shift, \$_[0]);

    return $self->_decode_macro( $$der_r, 'RSAPublicKey' );
}

sub _decode_rsa_within_pkcs8_or_die {
    my ($self, $pkcs8_hr) = @_;

    my $dec;
    try {
        $dec = $self->_decode_rsa( $pkcs8_hr->{'privateKey'} );
    }
    catch {
        die "Failed to parse RSA within PKCS8: $_";
    };

    return $dec;
}

sub _decode_rsa_public_within_pkcs8_or_die {
    my ($self, $pkcs8_hr) = @_;

    my $dec;
    try {
        $dec = $self->_decode_rsa_public( $pkcs8_hr->{'subjectPublicKey'}[0] );
    }
    catch {
        die "Failed to parse RSA within PKCS8: $_";
    };

    return $dec;
}

sub _decode_pkcs8 {
    my ($self, $der_r) = (shift, \$_[0]);

    return $self->_decode_macro( $$der_r, 'PrivateKeyInfo' );
}

sub _decode_pkcs8_public {
    my ($self, $der_r) = (shift, \$_[0]);

    return $self->_decode_macro( $$der_r, 'SubjectPublicKeyInfo' );
}

sub _new_public {
    my ($self, $parsed_hr) = @_;

    local $parsed_hr->{'exponent'} = $parsed_hr->{'publicExponent'};

    Crypt::Perl::Load::module('Crypt::Perl::RSA::PublicKey');
    return Crypt::Perl::RSA::PublicKey->new($parsed_hr);
}

sub _new_private {
    my ($self, $parsed_hr) = @_;

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
