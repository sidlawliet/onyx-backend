#include "auth/jwt_manager.hpp"
#include "utils/crypto_utils.hpp"
#include <chrono>

using json = nlohmann::json;

namespace trustgraph::auth {

JwtManager::JwtManager(std::string secret_key, int64_t default_expiry_seconds)
    : secret_key_(std::move(secret_key)), default_expiry_seconds_(default_expiry_seconds) {}

std::string JwtManager::create_token(const JwtTokenClaims& claims) const {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    int64_t iat = claims.iat != 0 ? claims.iat : now;
    int64_t exp = claims.exp != 0 ? claims.exp : (iat + default_expiry_seconds_);

    json header = {
        {"alg", "HS256"},
        {"typ", "JWT"}
    };

    json payload = {
        {"sub", claims.user_id},
        {"user_id", claims.user_id},
        {"username", claims.username},
        {"role", claims.role},
        {"iat", iat},
        {"exp", exp}
    };

    if (claims.associated_account_id.has_value()) {
        payload["associated_account_id"] = *claims.associated_account_id;
    } else {
        payload["associated_account_id"] = nullptr;
    }

    std::string header_encoded = crypto::base64url_encode(header.dump());
    std::string payload_encoded = crypto::base64url_encode(payload.dump());
    std::string unsigned_token = header_encoded + "." + payload_encoded;

    auto sig_bytes = crypto::hmac_sha256_bytes(secret_key_, unsigned_token);
    std::string signature_encoded = crypto::base64url_encode(sig_bytes.data(), sig_bytes.size());

    return unsigned_token + "." + signature_encoded;
}

std::optional<JwtTokenClaims> JwtManager::verify_token(const std::string& token) const {
    size_t first_dot = token.find('.');
    if (first_dot == std::string::npos) return std::nullopt;

    size_t second_dot = token.find('.', first_dot + 1);
    if (second_dot == std::string::npos) return std::nullopt;

    // Check no trailing dots
    if (token.find('.', second_dot + 1) != std::string::npos) return std::nullopt;

    std::string header_encoded = token.substr(0, first_dot);
    std::string payload_encoded = token.substr(first_dot + 1, second_dot - first_dot - 1);
    std::string signature_encoded = token.substr(second_dot + 1);

    std::string unsigned_token = header_encoded + "." + payload_encoded;

    // Verify HMAC signature
    auto expected_sig_bytes = crypto::hmac_sha256_bytes(secret_key_, unsigned_token);
    std::string expected_sig_encoded = crypto::base64url_encode(expected_sig_bytes.data(), expected_sig_bytes.size());

    if (!crypto::constant_time_compare(signature_encoded, expected_sig_encoded)) {
        return std::nullopt;
    }

    try {
        // Decode header
        std::string header_json_str = crypto::base64url_decode(header_encoded);
        auto header = json::parse(header_json_str);
        if (!header.contains("alg") || header["alg"] != "HS256") {
            return std::nullopt;
        }

        // Decode payload
        std::string payload_json_str = crypto::base64url_decode(payload_encoded);
        auto payload = json::parse(payload_json_str);

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        if (!payload.contains("exp") || !payload["exp"].is_number()) {
            return std::nullopt;
        }
        int64_t exp = payload["exp"].get<int64_t>();
        if (now > exp) {
            return std::nullopt; // Expired
        }

        JwtTokenClaims claims;
        if (payload.contains("user_id") && payload["user_id"].is_string()) {
            claims.user_id = payload["user_id"].get<std::string>();
        } else if (payload.contains("sub") && payload["sub"].is_string()) {
            claims.user_id = payload["sub"].get<std::string>();
        }

        if (payload.contains("username") && payload["username"].is_string()) {
            claims.username = payload["username"].get<std::string>();
        }

        if (payload.contains("role") && payload["role"].is_string()) {
            claims.role = payload["role"].get<std::string>();
        }

        if (payload.contains("associated_account_id") && payload["associated_account_id"].is_string()) {
            claims.associated_account_id = payload["associated_account_id"].get<std::string>();
        } else {
            claims.associated_account_id = std::nullopt;
        }

        claims.exp = exp;
        if (payload.contains("iat") && payload["iat"].is_number()) {
            claims.iat = payload["iat"].get<int64_t>();
        }

        return claims;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace trustgraph::auth
