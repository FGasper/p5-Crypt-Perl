package Crypt::Perl::ASN1;

#Wrappers around basic methods to get exceptions thrown on errors.

use parent 'Convert::ASN1';

use Crypt::Perl::BigInt ();

sub new {
    my ($class, @opts) = @_;

    return $class->SUPER::new(
        encode => { bigint => 'Crypt::Perl::BigInt' },
        decode => { bigint => 'Crypt::Perl::BigInt' },
        @opts,
    );
}

sub prepare {
    my ( $self, $asn1_r ) = ( $_[0], \$_[1] );

    my $ret = $self->SUPER::prepare($$asn1_r);

    if ( !defined $ret ) {
        die sprintf( "Failed to prepare ASN.1 description: %s", $self->error() );
    }

    return $ret;
}

sub find {
    my ( $self, $macro ) = @_;

    return $self->SUPER::find($macro) || do {
        die sprintf( "Failed to find ASN.1 macro “$macro”: %s", $self->error() );
    };
}

sub encode {
    my ($self) = shift;

    return $self->SUPER::encode(@_) || do {
        die sprintf( "Failed to encode ASN.1 (args: @_): %s", $self->error() );
    };
}

sub decode {
    my ($self) = shift;

    return $self->SUPER::decode(@_) || do {
        die sprintf( "Failed to decode ASN.1 (@_): %s", $self->error() );
    };
}

1;
