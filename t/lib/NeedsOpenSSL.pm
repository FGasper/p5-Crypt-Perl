package NeedsOpenSSL;

use strict;
use warnings;

use Test::More;

sub SKIP_CLASS {
    my ($self) = @_;

    return 'No OpenSSL binary!' if !$self->_get_openssl();

    return;
}

sub _get_openssl {
    my ($self) = @_;

    return $self->{'_ossl_bin'} ||= do {
        my $bin = `which openssl`;
        die if $?;
        chomp $bin;

        note "Using OpenSSL binary: $bin";
        note `$bin version -a`;

        $bin;
    };
}

1;
