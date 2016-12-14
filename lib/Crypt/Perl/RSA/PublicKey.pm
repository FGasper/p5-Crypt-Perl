package Crypt::Perl::RSA::PublicKey;

use strict;
use warnings;

use parent qw(
    Class::Accessor::Fast
    Crypt::Perl::RSA::KeyBase
);

use Crypt::Perl::BigInt ();

BEGIN {
    __PACKAGE__->mk_ro_accessors('publicExponent');

    *exponent = \&publicExponent;
    *E = \&exponent;
}

sub new {
    my ($class, @args) = @_;

    my $self = $class->SUPER::new(@args);

    $self->{'publicExponent'} = Crypt::Perl::BigInt->new( $self->{'publicExponent'} );

    return $self;
}

sub to_der {
    my ($self) = @_;

    return $self->_to_der('RSAPublicKey');
}

1;
