#include "auth/password_hasher.hpp"
#include "utils/crypto_utils.hpp"
#include <sstream>
#include <vector>
#include <cstring>

namespace onyx::auth {

std::vector<uint8_t> PasswordHasher::pbkdf2_hmac_sha256(
    const std::string& password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations,
    size_t dkLen)
{
    std::vector<uint8_t> derived_key;
    derived_key.reserve(dkLen);

    uint32_t block_index = 1;
    while (derived_key.size() < dkLen) {
        // salt || INT_32_BE(block_index)
        std::vector<uint8_t> s_block = salt;
        s_block.push_back(static_cast<uint8_t>((block_index >> 24) & 0xFF));
        s_block.push_back(static_cast<uint8_t>((block_index >> 16) & 0xFF));
        s_block.push_back(static_cast<uint8_t>((block_index >> 8) & 0xFF));
        s_block.push_back(static_cast<uint8_t>(block_index & 0xFF));

        std::string s_block_str(reinterpret_cast<char*>(s_block.data()), s_block.size());
        auto u_prev = crypto::hmac_sha256_bytes(password, s_block_str);
        auto u_xor = u_prev;

        for (uint32_t i = 1; i < iterations; ++i) {
            std::string u_prev_str(reinterpret_cast<char*>(u_prev.data()), u_prev.size());
            u_prev = crypto::hmac_sha256_bytes(password, u_prev_str);
            for (size_t k = 0; k < u_xor.size(); ++k) {
                u_xor[k] ^= u_prev[k];
            }
        }

        for (size_t k = 0; k < u_xor.size() && derived_key.size() < dkLen; ++k) {
            derived_key.push_back(u_xor[k]);
        }
        ++block_index;
    }

    return derived_key;
}

std::string PasswordHasher::hash_password(const std::string& password, uint32_t iterations) {
    auto salt_bytes = crypto::get_random_bytes(SALT_LENGTH_BYTES);
    auto derived_key = pbkdf2_hmac_sha256(password, salt_bytes, iterations, KEY_LENGTH_BYTES);

    std::string salt_hex = crypto::to_hex(salt_bytes);
    std::string hash_hex = crypto::to_hex(derived_key);

    std::ostringstream oss;
    oss << "$pbkdf2-sha256$i=" << iterations << "$" << salt_hex << "$" << hash_hex;
    return oss.str();
}

bool PasswordHasher::verify_password(const std::string& password, const std::string& stored_hash) {
    // Expected format: $pbkdf2-sha256$i=<iter>$<salt_hex>$<hash_hex>
    if (stored_hash.rfind("$pbkdf2-sha256$", 0) != 0) {
        return false;
    }

    size_t first_dollar = stored_hash.find('$', 1);
    if (first_dollar == std::string::npos) return false;

    size_t second_dollar = stored_hash.find('$', first_dollar + 1);
    if (second_dollar == std::string::npos) return false;

    size_t third_dollar = stored_hash.find('$', second_dollar + 1);
    if (third_dollar == std::string::npos) return false;

    std::string iter_str = stored_hash.substr(first_dollar + 1, second_dollar - first_dollar - 1);
    if (iter_str.rfind("i=", 0) != 0) {
        return false;
    }
    uint32_t iterations = 0;
    try {
        iterations = std::stoul(iter_str.substr(2));
    } catch (...) {
        return false;
    }

    std::string salt_hex = stored_hash.substr(second_dollar + 1, third_dollar - second_dollar - 1);
    std::string expected_hash_hex = stored_hash.substr(third_dollar + 1);

    auto salt_bytes = crypto::from_hex(salt_hex);
    if (salt_bytes.empty()) {
        return false;
    }

    auto derived_key = pbkdf2_hmac_sha256(password, salt_bytes, iterations, KEY_LENGTH_BYTES);
    std::string actual_hash_hex = crypto::to_hex(derived_key);

    return crypto::constant_time_compare(actual_hash_hex, expected_hash_hex);
}

} // namespace onyx::auth
