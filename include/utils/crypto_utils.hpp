#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace trustgraph::crypto {

// Cryptographically secure random byte generation
std::vector<uint8_t> get_random_bytes(size_t count);
std::string get_random_hex(size_t byte_count);
std::string generate_uuid_v4();

// Constant-time string comparison to prevent timing attacks
bool constant_time_compare(const std::string& a, const std::string& b);

// SHA-256 Hashing
std::vector<uint8_t> sha256_bytes(const std::string& data);
std::string sha256_hex(const std::string& data);

// HMAC-SHA256
std::vector<uint8_t> hmac_sha256_bytes(const std::string& key, const std::string& data);
std::string hmac_sha256_hex(const std::string& key, const std::string& data);

// Base64 and Base64Url (RFC 7515 / RFC 4648)
std::string base64_encode(const uint8_t* data, size_t len);
std::string base64_encode(const std::string& data);
std::string base64_decode(const std::string& input);

std::string base64url_encode(const uint8_t* data, size_t len);
std::string base64url_encode(const std::string& data);
std::string base64url_decode(const std::string& input);

// Hex helpers
std::string to_hex(const uint8_t* data, size_t len);
std::string to_hex(const std::vector<uint8_t>& data);
std::vector<uint8_t> from_hex(const std::string& hex);

} // namespace trustgraph::crypto
