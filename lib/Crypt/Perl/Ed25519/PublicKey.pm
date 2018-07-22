package Crypt::Perl::Ed25519::PublicKey;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Crypt::Perl::Ed25519::PublicKey

=head1 SYNOPSIS

    # This expects an octet string.
    my $import_key = Crypt::Perl::Ed25519::PublicKey->new( $pub_str );

    $key->verify( $message, $signature ) or die "Invalid sig for msg!";

    #----------------------------------------------------------------------

    # Returns an octet string.
    my $pub_str = $key->get_public();

    # Returns an object
    my $pub_obj = $key->get_public_key();

=head1 DESCRIPTION

This class implements Ed25519 verification.

=cut

use parent qw( Crypt::Perl::Ed25519::KeyBase );

sub new {
    my ($class, $pub) = @_;

    return bless {
        _public => $pub,
        _public_ar => [ unpack 'C*', $pub ],
    }, $class;
}

1;
