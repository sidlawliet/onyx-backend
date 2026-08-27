#include <cassert>
#include <iostream>
#include <chrono>
#include "utils/crypto_utils.hpp"
#include "auth/password_hasher.hpp"
#include "auth/jwt_manager.hpp"

using namespace onyx;

void test_crypto_primitives() {
    std::cout << "[TEST] Running test_crypto_primitives..." << std::endl;

    // Test SHA-256 standard vector (empty string = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
    std::string empty_hash = crypto::sha256_hex("");
    assert(empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // Test SHA-256 known text "abc" = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    std::string abc_hash = crypto::sha256_hex("abc");
    assert(abc_hash == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Test Base64Url
    std::string test_str = "hello_world?#123";
    std::string encoded = crypto::base64url_encode(test_str);
    std::string decoded = crypto::base64url_decode(encoded);
    assert(decoded == test_str);

    // Test UUID v4 format
    std::string uuid = crypto::generate_uuid_v4();
    assert(uuid.length() == 36);
    assert(uuid[8] == '-' && uuid[13] == '-' && uuid[18] == '-' && uuid[23] == '-');
    assert(uuid[14] == '4'); // Version 4

    // Test constant-time compare
    assert(crypto::constant_time_compare("password123", "password123") == true);
    assert(crypto::constant_time_compare("password123", "password124") == false);
    assert(crypto::constant_time_compare("short", "longer_string") == false);

    std::cout << "  -> test_crypto_primitives passed!" << std::endl;
}

void test_password_hasher() {
    std::cout << "[TEST] Running test_password_hasher..." << std::endl;

    std::string raw_pass = "secure_password_123";
    std::string hash = auth::PasswordHasher::hash_password(raw_pass, 5000);

    assert(!hash.empty());
    assert(hash.rfind("$pbkdf2-sha256$", 0) == 0);

    // Verification with correct password
    bool verify_correct = auth::PasswordHasher::verify_password(raw_pass, hash);
    assert(verify_correct == true);

    // Verification with wrong password
    bool verify_wrong = auth::PasswordHasher::verify_password("wrong_password", hash);
    assert(verify_wrong == false);

    // Malformed hash
    assert(auth::PasswordHasher::verify_password(raw_pass, "invalid_hash_string") == false);

    std::cout << "  -> test_password_hasher passed!" << std::endl;
}

void test_jwt_manager() {
    std::cout << "[TEST] Running test_jwt_manager..." << std::endl;

    std::string secret = "test_super_secret_key_12345";
    auth::JwtManager jwt(secret, 3600); // 1 hour expiry

    auth::JwtTokenClaims claims;
    claims.user_id = "USR-8819A";
    claims.username = "siddharth_k";
    claims.role = "CONSUMER";
    claims.associated_account_id = "ACC-7A1B8C9D";

    std::string token = jwt.create_token(claims);
    assert(!token.empty());

    // Verify valid token
    auto claims_opt = jwt.verify_token(token);
    assert(claims_opt.has_value());
    assert(claims_opt->user_id == "USR-8819A");
    assert(claims_opt->username == "siddharth_k");
    assert(claims_opt->role == "CONSUMER");
    assert(claims_opt->associated_account_id == "ACC-7A1B8C9D");

    // Test token with wrong secret
    auth::JwtManager wrong_jwt("wrong_secret_key_999", 3600);
    auto invalid_claims = wrong_jwt.verify_token(token);
    assert(!invalid_claims.has_value());

    // Test tampered token payload
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);
    std::string header = token.substr(0, first_dot);
    std::string payload = token.substr(first_dot + 1, second_dot - first_dot - 1);
    std::string sig = token.substr(second_dot + 1);

    std::string tampered_payload = crypto::base64url_encode("{\"sub\":\"USR-HACKED\",\"role\":\"BANK_EMPLOYEE\"}");
    std::string tampered_token = header + "." + tampered_payload + "." + sig;
    assert(!jwt.verify_token(tampered_token).has_value());

    // Test expired token
    auth::JwtTokenClaims expired_claims = claims;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    expired_claims.iat = now - 1000;
    expired_claims.exp = now - 100; // In the past
    std::string expired_token = jwt.create_token(expired_claims);
    assert(!jwt.verify_token(expired_token).has_value());

    std::cout << "  -> test_jwt_manager passed!" << std::endl;
}

int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << "   RUNNING CRYPTO & JWT TEST SUITE        " << std::endl;
    std::cout << "==========================================" << std::endl;

    test_crypto_primitives();
    test_password_hasher();
    test_jwt_manager();

    std::cout << "All Crypto & JWT tests passed successfully!" << std::endl;
    return 0;
}
