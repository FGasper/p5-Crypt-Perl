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

    my $user_key = Crypt::Perl::ECDSA::Generate::by_name('prime256v1');

    my $cert = Crypt::Perl::X509v3->new(
        subject => [ commonName => 'Felipe' ],
        key => $user_key->get_public_key(),
        not_after => time + 3600,

        extensions => [
            [ 'basicConstraints', 1, 2 ],
            { critical => 1, extension => [ 'keyUsage', 'encipherOnly', 'digitalSignature', 'keyAgreement' ] },
            [ 'extKeyUsage', qw( serverAuth clientAuth codeSigning emailProtection timeStamping ocspSigning ) ],
            [ 'subjectAltName', dNSName => 'foo.com' ],
            [ 'authorityInfoAccess',
                [ 'ocsp', uniformResourceIdentifier => 'http://some.ocsp.uri' ],
                [ 'caIssuers', uniformResourceIdentifier => 'http://some.cab.uri' ],
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
        ],
    );

    #my $signing_key = Crypt::Perl::PK::parse_key( scalar `openssl genrsa` );
    #print "SIGNING:\n" . $signing_key->to_pem() . $/;

    #$cert->sign($signing_key, 'sha256');
    $cert->sign($user_key, 'sha256');

    my $pem = $cert->to_pem();
    print "$pem\n";

    my ($wfh, $fpath) = File::Temp::tempfile( CLEANUP => 1 );
    print {$wfh} $pem or die $!;
    close $wfh;

    print `openssl x509 -text -in $fpath -noout`;

    ok 1;
}
