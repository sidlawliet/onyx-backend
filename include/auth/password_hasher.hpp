#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace trustgraph::auth {

class PasswordHasher {
public:
    // Default iterations for PBKDF2-HMAC-SHA256
    static constexpr uint32_t DEFAULT_ITERATIONS = 100000;
    static constexpr size_t SALT_LENGTH_BYTES = 16;
    static constexpr size_t KEY_LENGTH_BYTES = 32;

    // Hashes password returning formatted string: $pbkdf2-sha256$i=100000$salt$hash
    static std::string hash_password(const std::string& password, uint32_t iterations = DEFAULT_ITERATIONS);

    // Constant-time verification of raw password against stored formatted hash
    static bool verify_password(const std::string& password, const std::string& stored_hash);

private:
    static std::vector<uint8_t> pbkdf2_hmac_sha256(const std::string& password, const std::vector<uint8_t>& salt, uint32_t iterations, size_t dkLen);
};

} // namespace trustgraph::auth
