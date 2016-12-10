package Crypt::Perl::X;

=encoding utf-8

=head1 NAME

Net::ACME::X - Exception objects for Crypt::Perl

=cut

use strict;
use warnings;

use File::Spec ();

sub create {
    my ( $type, @args ) = @_;

    my $x_package = "Crypt::Perl::X::$type";

    my $x_pkg_path = File::Spec->catfile( split m<::>, $x_package ) . '.pm';

    require $x_pkg_path;

    return $x_package->new(@args);
}

1;
