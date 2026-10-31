#pragma once

#include <crypto/crypto.hpp>
#include <curl/curl.h>
#include <helpers/utils.hpp>
#include <rfl/json.hpp>
#include <state/data-structures.hpp>

namespace endpoints::https {

struct SessionAuthorizationRequest {
  std::string action;
  std::string certificate_sha256;
  std::string app_id;
  std::string state_folder;
};

// The node agent owns this private Unix socket. It checks fresh Controller
// authority for this exact certificate, app and home on every launch/resume.
// No bearer token, pairing PIN, private key or remembered authorization is used.
inline bool
session_authorized(const wolf::config::PairedClient &client, const std::string &app_id, const std::string &action) {
  std::string socket = utils::get_env("WOLF_SESSION_AUTHORIZATION_SOCKET", "");
  if (socket.empty()) {
    // Standalone Wolf can retain ordinary pairing. Managed deployments enable
    // this explicitly and fail closed even if their socket is missing.
    return std::string(utils::get_env("WOLF_REQUIRE_SESSION_AUTHORIZATION", "FALSE")) != "TRUE";
  }
  if (socket.front() != '/' || socket.size() > 107) {
    return false;
  }
  auto cert = x509::cert_from_string(client.client_cert);
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_size = 0;
  if (!cert || X509_digest(cert.get(), EVP_sha256(), digest, &digest_size) != 1 || digest_size != 32) {
    return false;
  }
  constexpr char hex[] = "0123456789abcdef";
  std::string fingerprint;
  for (unsigned int i = 0; i < digest_size; ++i) {
    fingerprint += hex[digest[i] >> 4];
    fingerprint += hex[digest[i] & 15];
  }
  auto body = rfl::json::write(SessionAuthorizationRequest{action, fingerprint, app_id, client.app_state_folder});
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
  if (!curl) {
    return false;
  }
  auto headers = curl_slist_append(nullptr, "Content-Type: application/json");
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> owned_headers(headers, curl_slist_free_all);
  curl_easy_setopt(curl.get(), CURLOPT_UNIX_SOCKET_PATH, socket.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_URL, "http://localhost/authorize");
  curl_easy_setopt(curl.get(), CURLOPT_PROXY, "");
  curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT_MS, 500L);
  curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, 5000L);
  curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl.get(), CURLOPT_POST, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, +[](char *, size_t, size_t, void *) -> size_t { return 0; });
  auto result = curl_easy_perform(curl.get());
  long status = 0;
  curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
  return result == CURLE_OK && status == 204;
}

} // namespace endpoints::https
