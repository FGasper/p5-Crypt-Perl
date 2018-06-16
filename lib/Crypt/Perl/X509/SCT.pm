package Crypt::Perl::X509::SCT;

=head1 NAME

Crypt::Perl::X509::SCT

=head1 DESCRIPTION

This implements encoding of the structure defined in
L<https://tools.ietf.org/html/rfc6962#section-3.2>.

=head1 SEE ALSO

L<https://letsencrypt.org/2018/04/04/sct-encoding.html> has an
excellent walkthrough of the format that this module deals with.

=cut

BEGIN {
    local $@;
    if (!eval { pack 'q' }) {
        my $module = __PACKAGE__.
        die "$module uses 64-bit integers, which this perl ($^X, $^V) does not support.";
    }
}

use constant _TEMPLATE => join(
    q<>,
    'x',    # version 1
    'a32',  # key_id
    'Q>',   # timestamp
    'xx',   # zero-length extensions array
    'C',    # hash algorithm
    'C',    # signature algorithm
    'n',    # signature length
    'a*',   # signature
);

my @_TLS_hash_algorithm = (
    q<>,
    'md5',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha512',
);

my @_TLS_signature_algorithm = (
    'anonymous',
    'rsa',
    'dsa',
    'ecdsa',
);

=head1 FUNCTIONS

=head2 encode( %opts )

For now this always encodes a version 1 structure.

%opts is:

=over

=item * C<key_id> - 32-byte string

=item * C<timestamp> - integer (NB: milliseconds)

=item * C<hash_algorithm> - See
L<https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1>
for allowed values (e.g., C<sha256>).

=item * C<signature_algorithm> - Currently accepted values are
C<rsa> and C<ecdsa>. (cf. the URL for C<hash_algorithm> values)

=item * C<signature> - The signature (binary string).

=back

=cut

sub encode {
    my (%opts) = @_;

    my $hash_idx = _array_lookup(
        \@_TLS_hash_algorithm,
        $opts{'hash_algorithm'},
    );

    my $sig_idx = _array_lookup(
        \@_TLS_signature_algorithm,
        $opts{'signature_algorithm'},
    );

    if ( 32 != length $opts{'key_id'} ) {
        die sprintf("“key_id” (%v.02x) must be 32 bytes!", $opts{'key_id'});
    }
use Data::Dumper;
print Dumper(
        @opts{'key_id', 'timestamp'},
        $hash_idx,
        $sig_idx,
        $opts{'signature'},
);

    return pack _TEMPLATE(), (
        @opts{'key_id', 'timestamp'},
        $hash_idx,
        $sig_idx,
        length($opts{'signature'}),
        $opts{'signature'},
    );
}

# decode() will be easy to implement when needed

sub _array_lookup {
    my ($ar, $val, $name) = @_;

    my $found_idx;

    for my $idx ( 0 .. $#$ar ) {
        if ($val eq $ar->[$idx]) {
            $found_idx = $idx;
            last;
        }
    }

    if (!defined $found_idx) {
        die "Unrecognized “$name”: “$val”";
    }

    return $found_idx;
}

1;
