package Crypt::Perl::X509::Extension::subjectInfoAccess;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Crypt::Perl::X509::Extension::subjectInfoAccess

=head1 SYNOPSIS

    my $usage_obj = Crypt::Perl::X509::Extension::subjectInfoAccess->new(
    );

=head1 SEE ALSO

L<https://tools.ietf.org/html/rfc5280#section-4.2.2.2>

=cut

use parent qw( Crypt::Perl::X509::Extension );

use Crypt::Perl::X509::GeneralName ();

use constant OID => '1.3.6.1.5.5.7.1.11';

use constant CRITICAL => 0;

use constant ASN1 => Crypt::Perl::X509::GeneralName::ASN1() . <<END;
    AccessDescription  ::=  SEQUENCE {
        accessMethod          OBJECT IDENTIFIER,
        accessLocation        ANY -- GeneralName
    }

    subjectInfoAccess ::= SEQUENCE OF AccessDescription
END

my %method = (
    caRepository => '1.3.6.1.5.5.7.48.5',
    timeStamping => '1.3.6.1.5.5.7.48.3',
);

#TODO: Refactor with authorityInfoAccess
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
