#pragma once

#include <string>
#include "utils/json.hpp"

namespace onyx::models {

enum class AccountStatus {
    ACTIVE,
    FLAGGED,
    FROZEN
};

inline std::string account_status_to_string(AccountStatus status) {
    switch (status) {
        case AccountStatus::ACTIVE: return "ACTIVE";
        case AccountStatus::FLAGGED: return "FLAGGED";
        case AccountStatus::FROZEN: return "FROZEN";
    }
    return "ACTIVE";
}

inline AccountStatus string_to_account_status(const std::string& str) {
    if (str == "FLAGGED") return AccountStatus::FLAGGED;
    if (str == "FROZEN") return AccountStatus::FROZEN;
    return AccountStatus::ACTIVE;
}

struct Account {
    std::string account_id;
    std::string upi_id;
    std::string holder_name;
    std::string account_type = "SAVINGS"; // SAVINGS, CURRENT
    bool is_verified_merchant = false;
    double balance = 0.0;
    double risk_score = 0.0;
    AccountStatus status = AccountStatus::ACTIVE;
    std::string created_at;

    nlohmann::json to_json() const {
        return {
            {"account_id", account_id},
            {"upi_id", upi_id},
            {"holder_name", holder_name},
            {"customer_name", holder_name},
            {"account_type", account_type},
            {"is_verified_merchant", is_verified_merchant},
            {"balance", balance},
            {"risk_score", risk_score},
            {"status", account_status_to_string(status)},
            {"created_at", created_at}
        };
    }
};

} // namespace onyx::models
