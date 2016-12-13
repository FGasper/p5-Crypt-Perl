package Crypt::Perl::RSA::PublicKey;

use parent qw(
    Class::Accessor::Fast
    Crypt::Perl::RSA::KeyBase
);

BEGIN {
    __PACKAGE__->mk_ro_accessors('publicExponent');

    *exponent = \&publicExponent;
    *E = \&exponent;
}

sub to_der {
    my ($self) = @_;

    return $self->_to_der('RSAPublicKey');
}

1;
