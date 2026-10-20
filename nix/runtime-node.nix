{
  lib,
  nodejs_22,
  openssl_3_5,
}:
assert lib.versionAtLeast openssl_3_5.version "3.5.9";
{
  # Use the stock cached runtime. The package install check verifies Node's
  # reported OpenSSL version and the actual mapped library store paths.
  openssl = openssl_3_5;
  nodejs = nodejs_22;
}
