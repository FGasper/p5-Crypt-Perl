package Crypt::Perl::X509::Extension::keyUsage;

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Crypt::Perl::X509::Extension::keyUsage

=head1 SYNOPSIS

    my $usage_obj = Crypt::Perl::X509::Extension::keyUsage->new(
        qw(
            digitalSignature
            contentCommitment
            keyEncipherment
            dataEncipherment
            keyAgreement
            keyCertSign
            cRLSign
            encipherOnly
            decipherOnly
        )
    );

=head1 SEE ALSO

L<https://tools.ietf.org/html/rfc5280#section-4.2.1.3>

=cut

use parent qw( Crypt::Perl::X509::Extension );

use Crypt::Perl::X ();

use constant OID => '2.5.29.15';

use constant ASN1 => <<END;
    keyUsage ::= BIT STRING
END

use constant CRITICAL => 1;

#The original bit values are “little-endian”.
#We might as well transmogrify these values for ease of use here.
my %bits = (
    digitalSignature        => 15, # 0,
    nonRepudiation          => 14, # 1,
    contentCommitment       => 14, # 1,   #more recent name
    keyEncipherment         => 13, # 2,
    dataEncipherment        => 12, # 3,
    keyAgreement            => 11, # 4,
    keyCertSign             => 10, # 5,
    cRLSign                 =>  9, # 6,
    encipherOnly            =>  8, # 7,
    decipherOnly            =>  7, # 8,
);

sub new {
    my ($class, @usages) = @_;

    if (!@usages) {
        die Crypt::Perl::X::create('Generic', 'Need usages!');
    }

    return bless \@usages, $class;
}

sub _encode_params {
    my ($self) = @_;

#    my $data = [
#        map {
#            $usages{$_} || die( Crypt::Perl::X::create('Generic', "Unknown usage: “$_”") ),
#        } @$self,
#    ];

    my $chr = 0;
    for my $usage (@$self) {
        if (!defined $bits{$usage}) {
            die Crypt::Perl::X::create('Generic', "Unknown key usage: “$usage”");
        }

        $chr |= 2**$bits{$usage};
    }

    #return "\x80\x00";

    return pack 'n', $chr;
}

1;
