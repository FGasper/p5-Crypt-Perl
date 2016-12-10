package Crypt::Perl::Load;

use strict;
use warnings;

use File::Spec ();

sub module {
    my ($module) = @_;

    my $module_path = File::Spec->catfile( split m<::>, $module ) . '.pm';
    return require $module_path;
}

1;
