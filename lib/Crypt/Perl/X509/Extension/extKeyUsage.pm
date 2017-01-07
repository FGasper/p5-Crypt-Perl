package Crypt::Perl::X509::Extension::extKeyUsage;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Crypt::Perl::X509::Extension::extKeyUsage

=cut

use parent qw( Crypt::Perl::X509::Extension );

use Crypt::Perl::X ();

use constant OID => '2.5.29.37';

use constant ASN1 => <<END;
    extKeyUsage ::= SEQUENCE OF KeyPurposeId

    KeyPurposeId ::= OBJECT IDENTIFIER
END

my %usages = (
    serverAuth => '1.3.6.1.5.5.7.3.1',
    clientAuth => '1.3.6.1.5.5.7.3.2',
    codeSigning => '1.3.6.1.5.5.7.3.3',
    emailProtection => '1.3.6.1.5.5.7.3.4',
    timeStamping => '1.3.6.1.5.5.7.3.8',
    ocspSigning => '1.3.6.1.5.5.7.3.9',
);

sub new {
    my ($class, @purposes) = @_;

    if (!@purposes) {
        die Crypt::Perl::X::create('Generic', 'Need purposes!');
    }

    return bless \@purposes, $class;
}

sub _encode_params {
    my ($self) = @_;

    my $data = [
        map {
            $usages{$_} || die( Crypt::Perl::X::create('Generic', "Unknown usage: “$_”") ),
        } @$self,
    ];

    return $data;
}

1;
