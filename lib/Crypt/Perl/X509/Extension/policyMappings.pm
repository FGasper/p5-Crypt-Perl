package Crypt::Perl::X509::Extension::policyMappings;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Crypt::Perl::X509::Extension::policyMappings - X.509 policyMappings extension

=cut

use parent qw(
    Crypt::Perl::X509::Extension
);

use Crypt::Perl::X509::GeneralNames ();

use constant OID => '2.5.29.33';

use CRITICAL => 1;

use constant ASN1 => <<END;
    policyMappings ::= SEQUENCE OF SEQUENCE {
        issuerDomainPolicy  OBJECT IDENTIFIER,
        subjectDomainPolicy OBJECT IDENTIFIER
    }
END

1;
