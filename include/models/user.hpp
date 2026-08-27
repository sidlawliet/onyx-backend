#pragma once

#include <string>
#include <optional>
#include "utils/json.hpp"

namespace onyx::models {

enum class UserRole {
    CONSUMER,
    BANK_EMPLOYEE
};

inline std::string user_role_to_string(UserRole role) {
    switch (role) {
        case UserRole::CONSUMER: return "CONSUMER";
        case UserRole::BANK_EMPLOYEE: return "BANK_EMPLOYEE";
    }
    return "CONSUMER";
}

inline std::optional<UserRole> string_to_user_role(const std::string& str) {
    if (str == "CONSUMER") return UserRole::CONSUMER;
    if (str == "BANK_EMPLOYEE") return UserRole::BANK_EMPLOYEE;
    return std::nullopt;
}

struct User {
    std::string user_id;
    std::string username;
    std::string password_hash;
    std::string name;
    UserRole role;
    std::optional<std::string> associated_account_id;
    std::string created_at;

    nlohmann::json to_json_public() const {
        nlohmann::json j = {
            {"user_id", user_id},
            {"username", username},
            {"name", name.empty() ? username : name},
            {"role", user_role_to_string(role)}
        };
        if (associated_account_id.has_value()) {
            j["associated_account_id"] = *associated_account_id;
        } else {
            j["associated_account_id"] = nullptr;
        }
        return j;
    }
};

} // namespace onyx::models
