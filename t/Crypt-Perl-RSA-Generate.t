package t::Crypt::Perl::RSA::Generate;

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
use Test::FailWarnings;
use Test::Deep;
use Test::Exception;

use File::Temp;

use lib "$FindBin::Bin/lib";

use parent qw(
    NeedsOpenSSL
    TestClass
);

use Crypt::Format ();

use Crypt::Perl::BigInt ();

use Crypt::Perl::RSA::Generate ();

__PACKAGE__->new()->runtests() if !caller;

#----------------------------------------------------------------------

sub _REJECT_BIGINT_LIBS {
    return qw( Math::BigInt::Calc );
}

sub SKIP_CLASS {
    my ($self) = @_;

    my $bigint_lib = Crypt::Perl::BigInt->config()->{'lib'};

    if (!$self->{'_checked_lib'}) {
        $self->{'_checked_lib'} = 1;

        diag "Your Crypt::Perl::BigInt backend is “$bigint_lib”.";
    }


    if ( grep { $_ eq $bigint_lib } _REJECT_BIGINT_LIBS() ) {
        return "RSA key generation with “$bigint_lib” is probably too slow for now. Skipping …";
    }

return 'nonono';

    return;
}

sub test_generate : Tests(1) {
    my ($self) = @_;

    my $ossl_bin = $self->_get_openssl();

    my $CHECK_COUNT = 50;

    my $mod_length = 512;

    lives_ok(
        sub {
            for ( 1 .. $CHECK_COUNT ) {
                note "Key generation $_ …";

                my $exp = ( 3, 65537 )[int( 0.5 + rand )];

                my $key_obj = Crypt::Perl::RSA::Generate::create($mod_length, $exp);
                my $pem = $key_obj->to_pem();

                my ($fh, $path) = File::Temp::tempfile( CLEANUP => 1 );
                print {$fh} $pem or die $!;
                close $fh;

                my $ossl_out = `$ossl_bin rsa -check -in $path 2>&1`;
                die $ossl_out if $ossl_out !~ m<RSA key ok>;
                note "OK";
            }
        },
        "Generated and verified $CHECK_COUNT $mod_length-bit RSA keys",
    );

    return;
}

1;
