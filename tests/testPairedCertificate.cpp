#include <catch2/catch_test_macros.hpp>
#include <crypto/crypto.hpp>

TEST_CASE("Paired identity requires the exact client certificate", "[Crypto][Security]") {
  auto key = x509::generate_key();
  auto paired = x509::generate_x509(key);

  SECTION("A separately parsed copy of the paired certificate is accepted") {
    auto presented = x509::cert_from_string(x509::get_cert_pem(paired));
    REQUIRE_FALSE(x509::verification_error(paired, presented).has_value());
  }

  SECTION("An unrelated self-signed certificate is denied") {
    auto other = x509::generate_x509(x509::generate_key());
    REQUIRE(x509::verification_error(paired, other).has_value());
  }

  SECTION("An attacker-issued leaf with an unknown issuer is denied") {
    auto issuer_key = x509::generate_key();
    auto leaf = x509::generate_x509(x509::generate_key());
    auto issuer = X509_NAME_new();
    REQUIRE(issuer != nullptr);
    REQUIRE(X509_NAME_add_entry_by_txt(issuer,
                                       "CN",
                                       MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char *>("Unpaired issuer"),
                                       -1,
                                       -1,
                                       0) == 1);
    REQUIRE(X509_set_issuer_name(leaf.get(), issuer) == 1);
    X509_NAME_free(issuer);
    REQUIRE(X509_sign(leaf.get(), issuer_key.get(), EVP_sha256()) > 0);
    // The old verification callback accepted this leaf as ANY paired user
    // after overriding X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY.
    REQUIRE(x509::verification_error(paired, leaf).has_value());
  }

  SECTION("Another certificate using the paired public key is denied") {
    auto other = x509::generate_x509(key);
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(other.get()), 42) == 1);
    REQUIRE(X509_sign(other.get(), key.get(), EVP_sha256()) > 0);
    REQUIRE(x509::verification_error(paired, other).has_value());
  }

  SECTION("Clock skew does not invalidate an exact paired certificate") {
    REQUIRE(X509_gmtime_adj(X509_getm_notAfter(paired.get()), -3600) != nullptr);
    REQUIRE(X509_sign(paired.get(), key.get(), EVP_sha256()) > 0);
    auto presented = x509::cert_from_string(x509::get_cert_pem(paired));
    REQUIRE_FALSE(x509::verification_error(paired, presented).has_value());
  }

  SECTION("Missing certificates are denied") {
    x509::x509_ptr missing(nullptr, X509_free);
    REQUIRE(x509::verification_error(paired, missing).has_value());
    REQUIRE(x509::verification_error(missing, paired).has_value());
    REQUIRE(x509::verification_error(missing, missing).has_value());
  }
}
