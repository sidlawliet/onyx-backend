#pragma once

#include <string>
#include "utils/json.hpp"

namespace trustgraph::models {

enum class TransactionStatus {
    PENDING,
    COMPLETED,
    HELD,
    FLAGGED,
    REJECTED
};

inline std::string transaction_status_to_string(TransactionStatus status) {
    switch (status) {
        case TransactionStatus::PENDING: return "PENDING";
        case TransactionStatus::COMPLETED: return "COMPLETED";
        case TransactionStatus::HELD: return "HELD";
        case TransactionStatus::FLAGGED: return "FLAGGED";
        case TransactionStatus::REJECTED: return "REJECTED";
    }
    return "PENDING";
}

inline TransactionStatus string_to_transaction_status(const std::string& str) {
    if (str == "SUCCESS" || str == "COMPLETED") return TransactionStatus::COMPLETED;
    if (str == "HELD") return TransactionStatus::HELD;
    if (str == "FLAGGED") return TransactionStatus::FLAGGED;
    if (str == "FAILED" || str == "REJECTED") return TransactionStatus::REJECTED;
    return TransactionStatus::PENDING;
}

struct Transaction {
    std::string transaction_id;
    std::string sender_account_id;
    std::string receiver_account_id;
    double amount = 0.0;
    std::string transaction_type = "UPI"; // UPI, IMPS, NEFT
    TransactionStatus status = TransactionStatus::PENDING;
    std::string timestamp;

    nlohmann::json to_json() const {
        return {
            {"transaction_id", transaction_id},
            {"sender_account_id", sender_account_id},
            {"receiver_account_id", receiver_account_id},
            {"amount", amount},
            {"transaction_type", transaction_type},
            {"status", transaction_status_to_string(status)},
            {"timestamp", timestamp}
        };
    }
};

} // namespace trustgraph::models
