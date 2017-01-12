package Crypt::Perl::X509::Extension::authorityInfoAccess;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Crypt::Perl::X509::Extension::authorityInfoAccess

=cut

use parent qw( Crypt::Perl::X509::Extension );

use Crypt::Perl::X509::GeneralName ();
use Crypt::Perl::X ();

use constant OID => '1.3.6.1.5.5.7.1.1';

use constant ASN1 => Crypt::Perl::X509::GeneralName::ASN1() . <<END;
    authorityInfoAccess ::= SEQUENCE OF AccessDescription

    AccessDescription ::= SEQUENCE {
        accessMethod    OBJECT IDENTIFIER,
        accessLocation  ANY -- GeneralName
    }
END

my %method = (
    ocsp => '1.3.6.1.5.5.7.48.1',
    caIssuers => '1.3.6.1.5.5.7.48.2',
);

sub new {
    my ($class, @accessDescrs) = @_;

    if (!@accessDescrs) {
        die Crypt::Perl::X::create('Generic', 'Need access descriptions!');
    }

    return bless \@accessDescrs, $class;
}

sub _encode_params {
    my ($self) = @_;

    my $data = [
        map {
            {
                accessMethod => $method{$_->[0]} || die( Crypt::Perl::X::create('Generic', "Unknown method: “$_->[0]”") ),
                accessLocation => Crypt::Perl::X509::GeneralName->new( @{$_}[1,2] )->encode(),
            }
        } @$self,
    ];

    return $data;
}

1;
