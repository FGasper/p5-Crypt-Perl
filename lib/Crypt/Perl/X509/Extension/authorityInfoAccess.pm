package Crypt::Perl::X509::Extension::authorityInfoAccess;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Crypt::Perl::X509::Extension::authorityInfoAccess

=cut

use parent qw( Crypt::Perl::X509::Extension );

use Crypt::Perl::X ();

use constant OID => '1.3.6.1.5.5.7.1.1';

use constant ASN1 => <<END;
    authorityInfoAccess ::= SEQUENCE OF AccessDescription

    AccessDescription ::= SEQUENCE {
        accessMethod    OBJECT IDENTIFIER,
        accessLocation  GeneralName
    }

    -- TODO: refactor from PKCS10
    GeneralName ::= CHOICE {
        -- otherName                       [0]     OtherName,
        rfc822Name                      [1]     IA5String,
        dNSName                         [2]     IA5String,
        -- x400Address                     [3]     ORAddress,
        -- directoryName                   [4]     Name,
        -- ediPartyName                    [5]     EDIPartyName,
        uniformResourceIdentifier       [6]     IA5String,
        iPAddress                       [7]     OCTET STRING,
        registeredID                    [8]     OBJECT IDENTIFIER
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
                accessLocation => {
                    $_->[1] => $_->[2],
                },
            }
        } @$self,
    ];

    return $data;
}

1;
