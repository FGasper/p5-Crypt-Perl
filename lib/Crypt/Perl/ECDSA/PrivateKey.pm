package Crypt::Perl::ECDSA::PrivateKey;

use strict;
use warnings;

use parent qw( Crypt::Perl::ECDSA::KeyBase );

use Try::Tiny;

use Bytes::Random::Secure::Tiny ();

use Crypt::Perl::ASN1 ();
use Crypt::Perl::BigInt ();
use Crypt::Perl::PKCS8 ();
use Crypt::Perl::RNG ();
use Crypt::Perl::Math ();
use Crypt::Perl::ToDER ();
use Crypt::Perl::X ();

sub new_by_curve_name {
    my ($class, $key_parts, $curve_name) = @_;

    #We could store the curve name on here if looking it up
    #in to_der_with_curve_name() proves prohibitive.
    return $class->new(
        $key_parts,
        {
            namedCurve => Crypt::Perl::ECDSA::EC::DB::get_oid_for_curve_name($curve_name),
        },
    );
}

#Expects a hash ref:
sub new {
    my ($class, $key_parts, $curve_parts) = @_;

    my $self = {
        version => $key_parts->{'version'},
    };

    for my $k ( qw( private public ) ) {
        if ( try { $key_parts->{$k}->isa('Crypt::Perl::BigInt') } ) {
            $self->{$k} = $key_parts->{$k};
        }
        else {
            die "“$k” must be “Crypt::Perl::BigInt”, not “$key_parts->{$k}”!";
        }
    }

    #my $self = {
    #    version => $struct->{'version'},
    #    private => Crypt::Perl::BigInt->from_bytes($struct->{'privateKey'}),
    #    public => Crypt::Perl::BigInt->from_bytes($struct->{'publicKey'}[0]),
    #
    #    #for parsing
    #    public_bytes_r => \$struct->{'publicKey'}[0],
    #};

    bless $self, $class;

    $self->_add_params( $curve_parts );

    return $self;
}

sub _make_asn1_key_parts {
}

sub _get_private_der {
    my ($self, $method) = @_;

    my $private_str = $self->{'private'}->as_bytes();

    #XXX Circular dependency
    use Crypt::Perl::ECDSA::Parser ();
    return $self->$method(
        'ECPrivateKey',
        Crypt::Perl::ECDSA::Parser::ASN1_PRIVATE() . Crypt::Perl::ECDSA::Parser::ASN1_Params(),
        {
            version => 1,
            privateKey => $self->_pad_bytes_for_asn1($private_str),
        },
    );
}

sub to_der_with_curve_name {
    my ($self) = @_;

    return $self->_get_private_der('_to_der_with_curve_name');
}

sub to_der_with_explicit_curve {
    my ($self) = @_;

    return $self->_get_private_der('_to_der_with_explicit_curve');
}

#Accepts der
#sub new {
#    my ($class, $der) = @_;
#
#    Crypt::Perl::ToDER::ensure_der($der);
#
#    my $asn1 = $class->_asn1();
#    my $asn1_ec = $asn1->find('ECPrivateKey');
#
#    my $struct;
#    try {
#        $struct = $asn1_ec->decode($der);
#    }
#    catch {
#        my $ec_err = $_;
#
#        my $asn1_pkcs8 = $asn1->find('PrivateKeyInfo');
#
#        try {
#            my $pk8_struct = $asn1_pkcs8->decode($der);
#
#            #It still might succeed, even if this is wrong, so don’t die().
#            if ( $pk8_struct->{'privateKeyAlgorithm'}{'algorithm'} ne $class->OID_ecPublicKey() ) {
#                warn "Unknown private key algorithm OID: “$pk8_struct->{'privateKeyAlgorithm'}{'algorithm'}”";
#            }
#
#            my $asn1_params = $asn1->find('EcpkParameters');
#            my $params = $asn1_params->decode($pk8_struct->{'privateKeyAlgorithm'}{'parameters'});
#
#            $struct = $asn1_ec->decode($pk8_struct->{'privateKey'});
#            $struct->{'parameters'} = $params;
#        }
#        catch {
#            die "Failed to decode private key as either ECDSA native ($ec_err) or PKCS8 ($_)";
#        };
#    };
#
#    my $self = {
#        version => $struct->{'version'},
#        private => Crypt::Perl::BigInt->from_bytes($struct->{'privateKey'}),
#        public => Crypt::Perl::BigInt->from_bytes($struct->{'publicKey'}[0]),
#
#        #for parsing
#        public_bytes_r => \$struct->{'publicKey'}[0],
#    };
##print "fieldType [$struct->{'parameters'}{'primeData'}{'fieldType'}]\n";
#
#    bless $self, $class;
#
#    $self->_add_params( $struct->{'parameters'} );
#
#    return $self;
#}

#$whatsit is probably a message digest, e.g., from SHA256
sub sign {
    my ($self, $whatsit) = @_;

    my $dgst = Crypt::Perl::BigInt->from_bytes( $whatsit );

    my $priv_num = $self->{'private'}; #Math::BigInt->from_hex( $priv_hex );

    my $n = $self->_curve()->{'n'}; #$curve_data->{'n'};

    my $key_len = $self->max_sign_bits();
    my $dgst_len = $dgst->bit_length();
    if ( $dgst_len > $key_len ) {
        die Crypt::Perl::X::create('TooLongToSign', $key_len, $dgst_len );
    }

    #isa ECPoint
    my $G = $self->G();
#printf "G.x: %s\n", $G->{'x'}->to_bigint()->as_hex();
#printf "G.y: %s\n", $G->{'y'}->to_bigint()->as_hex();
#printf "G.z: %s\n", $G->{'z'}->as_hex();

    my ($k, $r);

    do {
        $k = Crypt::Perl::Math::randint($n);
#print "once\n";
#printf "big random: %s\n", $k->as_hex();
#$k = Crypt::Perl::BigInt->new("98452900523450592996995215574085435893040452563985855319633891614520662229711");
#printf "k: %s\n", $k->bstr();
        my $Q = $G->multiply($k);   #$Q isa ECPoint
#printf "Q.x: %s\n", $Q->{'x'}->to_bigint()->as_hex();
#printf "Q.y: %s\n", $Q->{'y'}->to_bigint()->as_hex();
#printf "Q.z: %s\n", $Q->{'z'}->as_hex();
        $r = $Q->get_x()->to_bigint()->bmod($n);
    } while ($r <= 0);

#printf "k: %s\n", $k->as_hex();
#printf "n: %s\n", $n->as_hex();
#printf "e: %s\n", $dgst->as_hex();
#printf "d: %s\n", $priv_num->as_hex();
#printf "r: %s\n", $r->as_hex();

    my $s = $k->bmodinv($n);
    $s *= ( $dgst + ( $priv_num * $r ) );
    $s %= $n;

    return $self->_serialize_sig( $r, $s );
}

#could be faster; see JS implementation?
sub _getBigRandom {
    my ($limit) = @_;

    my $lim_bytes = length($limit->as_hex()) - 2;
    $lim_bytes /= 2;

    my $r;
    do {
        $r = Crypt::Perl::BigInt->from_hex( Crypt::Perl::RNG::bytes_hex($lim_bytes) );
    } while $r > $limit;

    return $r;
}

sub _serialize_sig {
    my ($self, $r, $s) = @_;

    my $asn1 = Crypt::Perl::ASN1->new()->prepare( $self->ASN1_SIGNATURE() );
    return $asn1->encode( r => $r, s => $s );
}

1;
