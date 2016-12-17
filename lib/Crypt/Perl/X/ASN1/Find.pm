package Crypt::Perl::X::ASN1::Find;

#This shouldn’t happen as long as the commands come from this library.
#But, for completeness …

use strict;
use warnings;

use parent 'Crypt::Perl::X::Base';

sub new {
    my ($class, $macro, $error) = @_;

    return $class->SUPER::new( "Failed to find ASN.1 macro “$macro”: $error", { macro => $macro, error => $error } );
}

1;
