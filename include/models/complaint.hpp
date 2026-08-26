#pragma once

#include <string>
#include "utils/json.hpp"

namespace trustgraph::models {

struct FraudComplaint {
    std::string complaint_id;
    std::string complainant_account_id;
    std::string suspect_account_id;
    std::string transaction_id;
    double amount = 0.0;
    std::string scam_category;
    std::string description;
    std::string status = "SUBMITTED"; // "SUBMITTED", "UNDER_INVESTIGATION", "RESOLVED", "REJECTED"
    std::string created_at;

    nlohmann::json to_json() const {
        return {
            {"complaint_id", complaint_id},
            {"complainant_account_id", complainant_account_id},
            {"suspect_account_id", suspect_account_id},
            {"transaction_id", transaction_id},
            {"amount", amount},
            {"scam_category", scam_category},
            {"description", description},
            {"status", status},
            {"created_at", created_at}
        };
    }
};

} // namespace trustgraph::models
