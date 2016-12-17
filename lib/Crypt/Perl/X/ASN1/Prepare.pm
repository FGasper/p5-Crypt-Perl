package Crypt::Perl::X::ASN1::Prepare;

#This shouldn’t happen as long as the templates come from this library.
#But, for completeness …

use strict;
use warnings;

use parent 'Crypt::Perl::X::Base';

sub new {
    my ($class, $template, $error) = @_;

    return $class->SUPER::new( "Failed to prepare ASN.1 template: $error", { asn => $template, error => $error } );
}

1;
