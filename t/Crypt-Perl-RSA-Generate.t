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

    return;
}

sub test_generate : Tests(50) {
    my ($self) = @_;

my $ok = !eval {

    my $ossl_bin = $self->_get_openssl();

    my $CHECK_COUNT = $self->num_tests();

diag "check count: $CHECK_COUNT";

    my $mod_length = 512;

  SKIP:
    for ( 1 .. $CHECK_COUNT ) {
        diag "Key generation $_ …";

        my $exp = ( 3, 65537 )[int( 0.5 + rand )];
diag "exponent: $exp\n";

        my $key_obj = Crypt::Perl::RSA::Generate::create($mod_length, $exp);
diag "generated key";
        my $pem = $key_obj->to_pem();
diag "PEM:\n$pem";

        my ($fh, $path) = File::Temp::tempfile( CLEANUP => 1 );
        print {$fh} $pem or do {
            diag "Failed to write PEM to temp file: $!";
            skip "Failed to write PEM to temp file: $!", 1;
        };
        close $fh;
diag "wrote temp file";

        my $ossl_out = OpenSSL_Control::run( qw(rsa -check -in), $path );
diag $ossl_out;
        like( $ossl_out, qr<RSA key ok>, "key generation (run $_, exponent: $exp)" ) or do {
            diag $pem;
            diag $ossl_out;
        };
    }

1;
};
diag $@ if !$ok;

diag "returning";

    return;
}

1;
