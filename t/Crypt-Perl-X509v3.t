package t::Crypt::Perl::X509v3;

use strict;
use warnings;

BEGIN {
    if ( $^V ge v5.10.1 ) {
        require autodie;
    }
}

use FindBin;
use lib "$FindBin::Bin/../lib";

use Test::More;
use Test::NoWarnings;
use Test::Deep;
use Test::Exception;

use File::Temp;

use lib "$FindBin::Bin/lib";

use OpenSSL_Control ();

use parent qw(
    Test::Class
    NeedsOpenSSL
);

use Crypt::Perl::ECDSA::Generate ();
use Crypt::Perl::PK ();

use Crypt::Perl::X509v3 ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

sub test_creation : Tests(2) {

    my $rsa_1024 = <<END;
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDfjCeysJZyne/M7Zzvl3Ym2dVcu3eXh19/2Z4C/ZkPnLFrbOht
MgqKJ7qFtK961laVlmwhI/mnnzaCuYhkOH1COBT6jIdAMvzzBDoDyf6DBLjgSxlw
Q2BGD/JWRKbKSRVBSPtMkuDynHAxYpyY6i73iBLUiHcN7mZ7uq4WFPJEaQIDAQAB
AoGBAJ4XFP/2h/74mFyZcZGy0Fi7VntlDDc6Ahx9PpSo2XTEAGiTNW/7op5/aBYk
aLD7IXJaVY++TFDxdHBQWxddJ565gNcP7QRfS7IGt3QNiRb86m1SvjGfvYuVZfPy
DI62wTvSeqcxTCKBaUJLQr3uAI2atrNuT2Q+X/D7zf0IUllxAkEA8Yk5Mn2dicEa
uHSFlRipmv9PmDk1lPicoEW9Zfu0fP9MlO4cO6sgSg/nFzLEXsH3xoyeMtpQcaka
WQHBnlE9NQJBAOzvKj7HSlZ38HnOvwf1G6KCnC/Q1UODIlutDb+EqiWiRHcJJyZW
B82lgeiJP0Wnt3CuDYVWM43wZ6ycgBYw9OUCQQCsTdgfzLy1qKwHKhihZBaaG8gM
L8OpojEZpKaYOhdnlDhthe9eIZXHP9D7G5w6fOTlHys728HHU3sYQ8h7yDiBAkEA
vaHJ+Qb+e2hxgrwzbwYBQTcyFJ8bIXbCOAewujlPCOHv1CnyOJ+gjTpLWDcI+hH7
IudbkP1mM9NW1vNHHPu/9QJAS52UIkaqTcfmwXSRFO9B27dN1SXpLfGEqVN+4V6f
owy+09/YdTipcfDokqMjabERaUwG+iEananaTW2nAkx3Kg==
-----END RSA PRIVATE KEY-----
END

    #my $user_key = Crypt::Perl::ECDSA::Generate::by_name('prime256v1');
    my $user_key = Crypt::Perl::PK::parse_key( $rsa_1024 );

    my $i = 2;

    my $cert = Crypt::Perl::X509v3->new(
        #subject => [ commonName => "Felipe$i" ],
        issuer => [
            [ commonName => "Felipe" . (1 + $i) , surname => 'theIssuer' ],
            [ givenName => 'separate RDNs' ],
        ],
        subject => [ commonName => "Felipe" . (1 + $i), surname => 'theSubject' ],
        key => $user_key->get_public_key(),
        not_after => time + 360000000,

        extensions => [
            [ 'basicConstraints', 1 ],
            [ 'keyUsage', 'keyCertSign', 'keyEncipherment', 'keyAgreement', 'digitalSignature', 'keyAgreement' ],
            [ 'extKeyUsage', qw( serverAuth clientAuth codeSigning emailProtection timeStamping OCSPSigning ) ],
            [ 'subjectKeyIdentifier', "\x00\x01\x02" ],
            [ 'issuerAltName',
                [ dNSName => 'fooissuer.com' ],
                [ directoryName => [
                    givenName => 'Ludwig',
                    surname => 'van Beethoven',
                ] ],
            ],
            [ 'subjectAltName',
                [ dNSName => 'foo.com' ],
                [ directoryName => [
                    givenName => 'Felipe',
                    surname => 'Gasper',
                ] ],
                #[ ediPartyName => {
                #    nameAssigner => 'the nameAssigner',
                #    partyName => 'the partyName',
                #} ],
            ],
            [ 'authorityKeyIdentifier',
                keyIdentifier => "\x77\x88\x99",
                authorityCertIssuer => [
                    [ dNSName => 'foo.com' ],
                    [ directoryName => [
                        givenName => 'Margaret',
                        surname => 'Attia',
                    ] ],
                ],
                authorityCertSerialNumber => 2566678,
            ],
            [ 'authorityInfoAccess',
                [ 'ocsp', uniformResourceIdentifier => 'http://some.ocsp.uri' ],
                [ 'caIssuers', uniformResourceIdentifier => sprintf("http://caissuers.x%d.tld", 1 + $i) ],
            ],
            [ 'certificatePolicies',
                [ 'organization-validated' ],
                [ '1.3.6.1.4.1.6449.1.2.2.52',
                    [ cps => 'https://cps.uri' ],
                    [ unotice => {
                        noticeRef => {
                            organization => 'FooFoo',
                            noticeNumbers => [ 12, 23, 34 ],
                        },
                        explicitText => 'apple',
                    } ],
                ],
            ],
            [ 'nameConstraints',
                permitted => [
                    [ dNSName => 'haha.tld', 1, 4 ],
                ],
                excluded => [
                    [ dNSName => 'fofo.tld', 7 ],
                    [ rfc822Name => 'haha@fofo.tld' ],
                ],
            ],
            [ 'policyConstraints', requireExplicitPolicy => 4, inhibitPolicyMapping => 6 ],
            [ inhibitAnyPolicy => 7 ],
            [ 'subjectInfoAccess',
                [ 'caRepository', uniformResourceIdentifier => 'http://some.car.uri' ],
                [ 'timeStamping', uniformResourceIdentifier => 'http://some.timeStamping.uri' ],
            ],
            [ 'tlsFeature' => 'status_request_v2' ],
            [ 'noCheck' ],
            [ 'policyMappings',
                {
                    subject => 'anyPolicy',
                    issuer => '1.2.3.4',
                },
                {
                    subject => '5.6.7.8',
                    issuer => 'anyPolicy',
                },
            ],
            [ 'cRLDistributionPoints',
                {
                    distributionPoint => {
                        fullName => [
                            [ uniformResourceIdentifier => 'http://myhost.com/myca.crl' ],
                            [ dNSName => 'full.name2.tld' ],
                        ],
                    },
                    reasons => [ 'unused', 'privilegeWithdrawn' ],
                },
                {
                    distributionPoint => {
                        nameRelativeToCRLIssuer => [
                            commonName => 'common',
                            surname => 'Jones',
                        ],
                    },
                    cRLIssuer => [
                        [ directoryName => [ commonName => 'thecommon' ] ],
                    ],
                },
            ],
            [ 'freshestCRL',
                {
                    distributionPoint => {
                        fullName => [
                            [ uniformResourceIdentifier => 'http://myhost.com/myca.crl' ],
                            [ dNSName => 'full.name2.tld' ],
                        ],
                    },
                    reasons => [ 'unused', 'privilegeWithdrawn' ],
                },
                {
                    distributionPoint => {
                        nameRelativeToCRLIssuer => [
                            commonName => 'common',
                            surname => 'Jones',
                        ],
                    },
                    cRLIssuer => [
                        [ directoryName => [ commonName => 'thecommon' ] ],
                    ],
                },
            ],
            [ 'ct_precert_poison' ],
            [
                'ct_precert_scts',
                {
                    timestamp => 1,
                    key_id => pack( 'H*', 'ee4bbdb775ce60bae142691fabe19e66a30f7e5fb072d88300c47b897aa8fdcb'),
                    hash_algorithm => 'sha256',
                    signature_algorithm => 'ecdsa',
                    signature => pack( 'H*', '3045022100e6fd1355f87c62d18d3f9628ffd074223764c947092bf3965c2584415b91472002200173b64dee1dcba40bd871c53073efd931acceec59368bdb97979ff07f9301c5'),
                },
                {
                    timestamp => 100100,
                    key_id => pack( 'H*', 'db74afeecb29ecb1feca3e716d2ce5b9aabb36f7847183c75d9d4f37b61fbf64' ),
                    hash_algorithm => 'sha256',
                    signature_algorithm => 'ecdsa',
                    signature => pack( 'H*', '3046022100ac559e93ccd09148e802e54ad3f7832e0464c0c071eb64b6d3fd52f2cf7fabe0022100d83199b57a1c4f80267901984525970757213a44b982d4a3c4903b3a62552fb2'),
                },
            ],
            #[ 'subjectDirectoryAttributes',
            #    [ commonName => 'foo', 'bar' ],
            #],
        ],
    );

    my $signing_key = Crypt::Perl::PK::parse_key( scalar `openssl genrsa` );
    #print "SIGNING:\n" . $signing_key->to_pem() . $/;

    #$cert->sign($signing_key, 'sha256');
    $cert->sign($user_key, 'sha256');

    my $pem = $cert->to_pem() or die "No PEM?!?";
    print "$pem\n";

    my ($wfh, $fpath) = File::Temp::tempfile( CLEANUP => 1 );
    print {$wfh} $pem or die $!;
    close $wfh;

    my $ossl_bin = OpenSSL_Control::openssl_bin();

    diag scalar `$ossl_bin asn1parse -i -dump -in $fpath`;
    cmp_ok($?, '==', 0, 'asn1parse succeeds' );

    diag scalar `$ossl_bin x509 -text -in $fpath -noout`;
    cmp_ok($?, '==', 0, 'x509 parses OK');

    return;
}
