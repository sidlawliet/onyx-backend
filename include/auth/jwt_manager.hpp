#pragma once

#include <string>
#include <optional>
#include <cstdint>
#include "utils/json.hpp"

namespace trustgraph::auth {

struct JwtTokenClaims {
    std::string user_id;
    std::string username;
    std::string role; // "CONSUMER" or "BANK_EMPLOYEE"
    std::optional<std::string> associated_account_id;
    int64_t iat = 0;
    int64_t exp = 0;
};

class JwtManager {
public:
    explicit JwtManager(std::string secret_key, int64_t default_expiry_seconds = 86400);

    // Creates a signed JWT token
    std::string create_token(const JwtTokenClaims& claims) const;

    // Verifies signature, expiration, and extracts claims. Returns std::nullopt if invalid or expired.
    std::optional<JwtTokenClaims> verify_token(const std::string& token) const;

    // Direct accessors
    const std::string& get_secret_key() const { return secret_key_; }
    int64_t get_default_expiry_seconds() const { return default_expiry_seconds_; }

private:
    std::string secret_key_;
    int64_t default_expiry_seconds_;
};

} // namespace trustgraph::auth
