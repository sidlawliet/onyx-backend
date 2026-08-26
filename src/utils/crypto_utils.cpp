#include "utils/crypto_utils.hpp"
#include <iomanip>
#include <sstream>
#include <random>
#include <cstring>
#include <array>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fstream>
#endif

namespace trustgraph::crypto {

// ---------------------------------------------------------------------------
// CSPRNG
// ---------------------------------------------------------------------------
std::vector<uint8_t> get_random_bytes(size_t count) {
    std::vector<uint8_t> buffer(count);
#ifdef _WIN32
    HCRYPTPROV hCryptProv = 0;
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CryptGenRandom(hCryptProv, static_cast<DWORD>(count), buffer.data());
        CryptReleaseContext(hCryptProv, 0);
        return buffer;
    }
#else
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (urandom.is_open()) {
        urandom.read(reinterpret_cast<char*>(buffer.data()), count);
        urandom.close();
        return buffer;
    }
#endif
    // Fallback standard PRNG seeded with random_device
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint16_t> dis(0, 255);
    for (size_t i = 0; i < count; ++i) {
        buffer[i] = static_cast<uint8_t>(dis(gen));
    }
    return buffer;
}

std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string to_hex(const std::vector<uint8_t>& data) {
    return to_hex(data.data(), data.size());
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string get_random_hex(size_t byte_count) {
    auto bytes = get_random_bytes(byte_count);
    return to_hex(bytes);
}

std::string generate_uuid_v4() {
    auto b = get_random_bytes(16);
    // Set version to 0100 (version 4)
    b[6] = (b[6] & 0x0F) | 0x40;
    // Set variant to 10xxxxxx
    b[8] = (b[8] & 0x3F) | 0x80;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) {
        oss << std::setw(2) << static_cast<int>(b[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) {
            oss << "-";
        }
    }
    return oss.str();
}

bool constant_time_compare(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    volatile uint8_t result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return result == 0;
}

// ---------------------------------------------------------------------------
// Standard SHA-256 Engine (FIPS 180-4)
// ---------------------------------------------------------------------------
namespace {
inline uint32_t rotr(uint32_t n, uint32_t d) {
    return (n >> d) | (n << (32 - d));
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

const std::array<uint32_t, 64> K256 = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
} // anonymous namespace

std::vector<uint8_t> sha256_bytes(const std::string& data) {
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8;
    std::vector<uint8_t> msg(data.begin(), data.end());
    msg.push_back(0x80);

    while ((msg.size() % 64) != 56) {
        msg.push_back(0x00);
    }

    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));
    }

    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(msg[chunk + i * 4]) << 24) |
                   (static_cast<uint32_t>(msg[chunk + i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(msg[chunk + i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(msg[chunk + i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K256[i] + w[i];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    std::vector<uint8_t> digest(32);
    const uint32_t h[8] = { h0, h1, h2, h3, h4, h5, h6, h7 };
    for (int i = 0; i < 8; ++i) {
        digest[i * 4] = static_cast<uint8_t>((h[i] >> 24) & 0xFF);
        digest[i * 4 + 1] = static_cast<uint8_t>((h[i] >> 16) & 0xFF);
        digest[i * 4 + 2] = static_cast<uint8_t>((h[i] >> 8) & 0xFF);
        digest[i * 4 + 3] = static_cast<uint8_t>(h[i] & 0xFF);
    }
    return digest;
}

std::string sha256_hex(const std::string& data) {
    auto digest = sha256_bytes(data);
    return to_hex(digest);
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------
std::vector<uint8_t> hmac_sha256_bytes(const std::string& key, const std::string& data) {
    const size_t block_size = 64;
    std::vector<uint8_t> k(block_size, 0);

    if (key.size() > block_size) {
        auto key_hash = sha256_bytes(key);
        std::copy(key_hash.begin(), key_hash.end(), k.begin());
    } else {
        std::copy(key.begin(), key.end(), k.begin());
    }

    std::vector<uint8_t> o_key_pad(block_size);
    std::vector<uint8_t> i_key_pad(block_size);

    for (size_t i = 0; i < block_size; ++i) {
        o_key_pad[i] = k[i] ^ 0x5c;
        i_key_pad[i] = k[i] ^ 0x36;
    }

    std::string inner_data(reinterpret_cast<char*>(i_key_pad.data()), block_size);
    inner_data.append(data);
    auto inner_hash = sha256_bytes(inner_data);

    std::string outer_data(reinterpret_cast<char*>(o_key_pad.data()), block_size);
    outer_data.append(reinterpret_cast<char*>(inner_hash.data()), inner_hash.size());

    return sha256_bytes(outer_data);
}

std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    auto digest = hmac_sha256_bytes(key, data);
    return to_hex(digest);
}

// ---------------------------------------------------------------------------
// Base64 and Base64Url (RFC 4648 / RFC 7515)
// ---------------------------------------------------------------------------
static const std::string b64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

std::string base64_encode(const uint8_t* data, size_t len) {
    std::string ret;
    int i = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];

    while (len--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += b64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int j = 0; (j < i + 1); j++)
            ret += b64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::string base64_encode(const std::string& data) {
    return base64_encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

static inline bool is_base64(uint8_t c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_decode(const std::string& input) {
    size_t in_len = input.size();
    int i = 0;
    int in_ = 0;
    uint8_t char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (input[in_] != '=') && is_base64(input[in_])) {
        char_array_4[i++] = input[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = static_cast<uint8_t>(b64_chars.find(char_array_4[i]));

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (int j = 0; j < 4; j++)
            char_array_4[j] = static_cast<uint8_t>(b64_chars.find(char_array_4[j]));

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (int j = 0; (j < i - 1); j++)
            ret += char_array_3[j];
    }

    return ret;
}

std::string base64url_encode(const uint8_t* data, size_t len) {
    std::string b64 = base64_encode(data, len);
    std::string url;
    url.reserve(b64.size());
    for (char c : b64) {
        if (c == '+') url.push_back('-');
        else if (c == '/') url.push_back('_');
        else if (c != '=') url.push_back(c);
    }
    return url;
}

std::string base64url_encode(const std::string& data) {
    return base64url_encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::string base64url_decode(const std::string& input) {
    std::string b64;
    b64.reserve(input.size() + 4);
    for (char c : input) {
        if (c == '-') b64.push_back('+');
        else if (c == '_') b64.push_back('/');
        else b64.push_back(c);
    }
    while (b64.size() % 4 != 0) {
        b64.push_back('=');
    }
    return base64_decode(b64);
}

} // namespace trustgraph::crypto
