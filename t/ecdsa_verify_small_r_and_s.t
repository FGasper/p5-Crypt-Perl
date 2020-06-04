#!/usr/bin/env perl

use strict;
use warnings;

use Crypt::Perl::ECDSA;
use Crypt::Perl::ECDSA::Generate;
use Crypt::Perl::ECDSA::Parse;
use Digest::SHA;

use Test::More;
use Test::FailWarnings;

my $data = {
          "algorithm" => "ECDSA",
          "generatorVersion" => "0.8r12",
          "header" => [
                        "Test vectors of type EcdsaVerify are meant for the verification",
                        "of ASN encoded ECDSA signatures."
                      ],
          "notes" => {
                       "BER" => "This is a signature with correct values for (r, s) but using some alternative BER encoding instead of DER encoding. Implementations should not accept such signatures to limit signature malleability.",
                       "EdgeCase" => "Edge case values such as r=1 and s=0 can lead to forgeries if the ECDSA implementation does not check boundaries and computes s^(-1)==0.",
                       "MissingZero" => "Some implementations of ECDSA and DSA incorrectly encode r and s by not including leading zeros in the ASN encoding of integers when necessary. Hence, some implementations (e.g. jdk) allow signatures with incorrect ASN encodings assuming that the signature is otherwise valid.",
                       "PointDuplication" => "Some implementations of ECDSA do not handle duplication and points at infinity correctly. This is a test vector that has been specially crafted to check for such an omission."
                     },
          "numberOfTests" => 387,
          "schema" => "ecdsa_verify_schema.json",
          "testGroups" => [
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "04a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac9575d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b",
                                         "wx" => "00a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957",
                                         "wy" => "5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d03010703420004a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac9575d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpxr2TeUSakpOAreSLWbOlBXOiKTJ\n0lUU2RCCyHJayVddR3I8j75YC7Np/snCZl2OMKQ1uZMmRUgufJ8R6HIpaw==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "small r and s",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "valid",
                                             "sig" => "3006020105020101",
                                             "tcId" => 290
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            },
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "046627cec4f0731ea23fc2931f90ebe5b7572f597d20df08fc2b31ee8ef16b15726170ed77d8d0a14fc5c9c3c4c9be7f0d3ee18f709bb275eaf2073e258fe694a5",
                                         "wx" => "6627cec4f0731ea23fc2931f90ebe5b7572f597d20df08fc2b31ee8ef16b1572",
                                         "wy" => "6170ed77d8d0a14fc5c9c3c4c9be7f0d3ee18f709bb275eaf2073e258fe694a5"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d030107034200046627cec4f0731ea23fc2931f90ebe5b7572f597d20df08fc2b31ee8ef16b15726170ed77d8d0a14fc5c9c3c4c9be7f0d3ee18f709bb275eaf2073e258fe694a5",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZifOxPBzHqI/wpMfkOvlt1cvWX0g\n3wj8KzHujvFrFXJhcO132NChT8XJw8TJvn8NPuGPcJuyderyBz4lj+aUpQ==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "small r and s",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "valid",
                                             "sig" => "3006020105020103",
                                             "tcId" => 291
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            },
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "045a7c8825e85691cce1f5e7544c54e73f14afc010cb731343262ca7ec5a77f5bfef6edf62a4497c1bd7b147fb6c3d22af3c39bfce95f30e13a16d3d7b2812f813",
                                         "wx" => "5a7c8825e85691cce1f5e7544c54e73f14afc010cb731343262ca7ec5a77f5bf",
                                         "wy" => "00ef6edf62a4497c1bd7b147fb6c3d22af3c39bfce95f30e13a16d3d7b2812f813"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d030107034200045a7c8825e85691cce1f5e7544c54e73f14afc010cb731343262ca7ec5a77f5bfef6edf62a4497c1bd7b147fb6c3d22af3c39bfce95f30e13a16d3d7b2812f813",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWnyIJehWkczh9edUTFTnPxSvwBDL\ncxNDJiyn7Fp39b/vbt9ipEl8G9exR/tsPSKvPDm/zpXzDhOhbT17KBL4Ew==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "small r and s",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "valid",
                                             "sig" => "3006020105020105",
                                             "tcId" => 292
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            },
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "04cbe0c29132cd738364fedd603152990c048e5e2fff996d883fa6caca7978c73770af6a8ce44cb41224b2603606f4c04d188e80bff7cc31ad5189d4ab0d70e8c1",
                                         "wx" => "00cbe0c29132cd738364fedd603152990c048e5e2fff996d883fa6caca7978c737",
                                         "wy" => "70af6a8ce44cb41224b2603606f4c04d188e80bff7cc31ad5189d4ab0d70e8c1"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d03010703420004cbe0c29132cd738364fedd603152990c048e5e2fff996d883fa6caca7978c73770af6a8ce44cb41224b2603606f4c04d188e80bff7cc31ad5189d4ab0d70e8c1",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEy+DCkTLNc4Nk/t1gMVKZDASOXi//\nmW2IP6bKynl4xzdwr2qM5Ey0EiSyYDYG9MBNGI6Av/fMMa1RidSrDXDowQ==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "small r and s",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "valid",
                                             "sig" => "3006020105020106",
                                             "tcId" => 293
                                           },
                                           {
                                             "comment" => "r is larger than n",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "invalid",
                                             "sig" => "3026022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632556020106",
                                             "tcId" => 294
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            },
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "044be4178097002f0deab68f0d9a130e0ed33a6795d02a20796db83444b037e13920f13051e0eecdcfce4dacea0f50d1f247caa669f193c1b4075b51ae296d2d56",
                                         "wx" => "4be4178097002f0deab68f0d9a130e0ed33a6795d02a20796db83444b037e139",
                                         "wy" => "20f13051e0eecdcfce4dacea0f50d1f247caa669f193c1b4075b51ae296d2d56"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d030107034200044be4178097002f0deab68f0d9a130e0ed33a6795d02a20796db83444b037e13920f13051e0eecdcfce4dacea0f50d1f247caa669f193c1b4075b51ae296d2d56",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES+QXgJcALw3qto8NmhMODtM6Z5XQ\nKiB5bbg0RLA34Tkg8TBR4O7Nz85NrOoPUNHyR8qmafGTwbQHW1GuKW0tVg==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "s is larger than n",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "invalid",
                                             "sig" => "3026020105022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc75fbd8",
                                             "tcId" => 295
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            },
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "04d0f73792203716afd4be4329faa48d269f15313ebbba379d7783c97bf3e890d9971f4a3206605bec21782bf5e275c714417e8f566549e6bc68690d2363c89cc1",
                                         "wx" => "00d0f73792203716afd4be4329faa48d269f15313ebbba379d7783c97bf3e890d9",
                                         "wy" => "00971f4a3206605bec21782bf5e275c714417e8f566549e6bc68690d2363c89cc1"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d03010703420004d0f73792203716afd4be4329faa48d269f15313ebbba379d7783c97bf3e890d9971f4a3206605bec21782bf5e275c714417e8f566549e6bc68690d2363c89cc1",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0Pc3kiA3Fq/UvkMp+qSNJp8VMT67\nujedd4PJe/PokNmXH0oyBmBb7CF4K/XidccUQX6PVmVJ5rxoaQ0jY8icwQ==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "small r and s^-1",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "valid",
                                             "sig" => "3027020201000221008f1e3c7862c58b16bb76eddbb76eddbb516af4f63f2d74d76e0d28c9bb75ea88",
                                             "tcId" => 296
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            },
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "044838b2be35a6276a80ef9e228140f9d9b96ce83b7a254f71ccdebbb8054ce05ffa9cbc123c919b19e00238198d04069043bd660a828814051fcb8aac738a6c6b",
                                         "wx" => "4838b2be35a6276a80ef9e228140f9d9b96ce83b7a254f71ccdebbb8054ce05f",
                                         "wy" => "00fa9cbc123c919b19e00238198d04069043bd660a828814051fcb8aac738a6c6b"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d030107034200044838b2be35a6276a80ef9e228140f9d9b96ce83b7a254f71ccdebbb8054ce05ffa9cbc123c919b19e00238198d04069043bd660a828814051fcb8aac738a6c6b",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESDiyvjWmJ2qA754igUD52bls6Dt6\nJU9xzN67uAVM4F/6nLwSPJGbGeACOBmNBAaQQ71mCoKIFAUfy4qsc4psaw==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "smallish r and s^-1",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "valid",
                                             "sig" => "302c02072d9b4d347952d6022100ef3043e7329581dbb3974497710ab11505ee1c87ff907beebadd195a0ffe6d7a",
                                             "tcId" => 297
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            },
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "047393983ca30a520bbc4783dc9960746aab444ef520c0a8e771119aa4e74b0f64e9d7be1ab01a0bf626e709863e6a486dbaf32793afccf774e2c6cd27b1857526",
                                         "wx" => "7393983ca30a520bbc4783dc9960746aab444ef520c0a8e771119aa4e74b0f64",
                                         "wy" => "00e9d7be1ab01a0bf626e709863e6a486dbaf32793afccf774e2c6cd27b1857526"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d030107034200047393983ca30a520bbc4783dc9960746aab444ef520c0a8e771119aa4e74b0f64e9d7be1ab01a0bf626e709863e6a486dbaf32793afccf774e2c6cd27b1857526",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc5OYPKMKUgu8R4PcmWB0aqtETvUg\nwKjncRGapOdLD2Tp174asBoL9ibnCYY+akhtuvMnk6/M93Tixs0nsYV1Jg==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "100-bit r and small s^-1",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "valid",
                                             "sig" => "3032020d1033e67e37b32b445580bf4eff0221008b748b74000000008b748b748b748b7466e769ad4a16d3dcd87129b8e91d1b4d",
                                             "tcId" => 298
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            },
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "045ac331a1103fe966697379f356a937f350588a05477e308851b8a502d5dfcdc5fe9993df4b57939b2b8da095bf6d794265204cfe03be995a02e65d408c871c0b",
                                         "wx" => "5ac331a1103fe966697379f356a937f350588a05477e308851b8a502d5dfcdc5",
                                         "wy" => "00fe9993df4b57939b2b8da095bf6d794265204cfe03be995a02e65d408c871c0b"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d030107034200045ac331a1103fe966697379f356a937f350588a05477e308851b8a502d5dfcdc5fe9993df4b57939b2b8da095bf6d794265204cfe03be995a02e65d408c871c0b",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWsMxoRA/6WZpc3nzVqk381BYigVH\nfjCIUbilAtXfzcX+mZPfS1eTmyuNoJW/bXlCZSBM/gO+mVoC5l1AjIccCw==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "small r and 100 bit s^-1",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "valid",
                                             "sig" => "302702020100022100ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
                                             "tcId" => 299
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            },
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "041d209be8de2de877095a399d3904c74cc458d926e27bb8e58e5eae5767c41509dd59e04c214f7b18dce351fc2a549893a6860e80163f38cc60a4f2c9d040d8c9",
                                         "wx" => "1d209be8de2de877095a399d3904c74cc458d926e27bb8e58e5eae5767c41509",
                                         "wy" => "00dd59e04c214f7b18dce351fc2a549893a6860e80163f38cc60a4f2c9d040d8c9"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d030107034200041d209be8de2de877095a399d3904c74cc458d926e27bb8e58e5eae5767c41509dd59e04c214f7b18dce351fc2a549893a6860e80163f38cc60a4f2c9d040d8c9",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHSCb6N4t6HcJWjmdOQTHTMRY2Sbi\ne7jljl6uV2fEFQndWeBMIU97GNzjUfwqVJiTpoYOgBY/OMxgpPLJ0EDYyQ==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "100-bit r and s^-1",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "valid",
                                             "sig" => "3032020d062522bbd3ecbe7c39e93e7c25022100ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
                                             "tcId" => 300
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            },
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "04083539fbee44625e3acaafa2fcb41349392cef0633a1b8fabecee0c133b10e99915c1ebe7bf00df8535196770a58047ae2a402f26326bb7d41d4d7616337911e",
                                         "wx" => "083539fbee44625e3acaafa2fcb41349392cef0633a1b8fabecee0c133b10e99",
                                         "wy" => "00915c1ebe7bf00df8535196770a58047ae2a402f26326bb7d41d4d7616337911e"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d03010703420004083539fbee44625e3acaafa2fcb41349392cef0633a1b8fabecee0c133b10e99915c1ebe7bf00df8535196770a58047ae2a402f26326bb7d41d4d7616337911e",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECDU5++5EYl46yq+i/LQTSTks7wYz\nobj6vs7gwTOxDpmRXB6+e/AN+FNRlncKWAR64qQC8mMmu31B1NdhYzeRHg==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "r and s^-1 are close to n",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "valid",
                                             "sig" => "3045022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6324d50220555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
                                             "tcId" => 301
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            },
                            {
                              "key" => {
                                         "curve" => "secp256r1",
                                         "keySize" => 256,
                                         "type" => "EcPublicKey",
                                         "uncompressed" => "048aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e1937387405bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf576d",
                                         "wx" => "008aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e19373874",
                                         "wy" => "05bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf576d"
                                       },
                              "keyDer" => "3059301306072a8648ce3d020106082a8648ce3d030107034200048aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e1937387405bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf576d",
                              "keyPem" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEius2inAnpNZKveo3OQwMHWom85ni\n2XNN4es9Dhk3OHQFvRODRxXh266bh1zwe9VeG2aRx/dTau87Gb96St9XbQ==\n-----END PUBLIC KEY-----",
                              "sha" => "SHA-256",
                              "tests" => [
                                           {
                                             "comment" => "s == 1",
                                             "flags" => [],
                                             "msg" => "313233343030",
                                             "result" => "valid",
                                             "sig" => "30250220555555550000000055555555555555553ef7a8e48d07df81a693439654210c70020101",
                                             "tcId" => 302
                                           }
                                         ],
                              "type" => "EcdsaVerify"
                            }
                          ]
        };

diag "Parsing...";

my $aref = $data->{testGroups};
for my $element (@$aref) {
    my $public = Crypt::Perl::ECDSA::Parse::public($element->{keyPem});
    my $bref = $element->{tests};

    for my $test (@$bref) {
        my $msg_bytes = pack "H*", $test->{msg};
        my $sig_bytes = pack "H*", $test->{sig};
        my $hash = Digest::SHA::sha256($msg_bytes);

            my $result = $public->verify($hash, $sig_bytes);

            is(
                $test->{result} eq "valid" || $test->{result} eq "acceptable",
                !!$result,
                "tcId: $test->{tcId}",
            );

    }
}

done_testing;
