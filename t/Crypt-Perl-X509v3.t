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

#use Crypt::Perl::X509::Name ();

use Crypt::Perl::X509v3 ();

if ( !caller ) {
    my $test_obj = __PACKAGE__->new();
    plan tests => $test_obj->expected_tests(+1);
    $test_obj->runtests();
}

#----------------------------------------------------------------------

sub test_creation : Tests(1) {

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
        subject => [ commonName => "Felipe$i" ],
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
                #keyIdentifier => "\x01\x02\x03",
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

    print `openssl asn1parse -i -dump -in $fpath`;
    diag scalar `openssl x509 -text -in $fpath -noout`;

    ok 1;
}
