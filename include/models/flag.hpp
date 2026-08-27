#pragma once

#include <string>
#include <vector>
#include "utils/json.hpp"

namespace onyx::models {

struct TransactionFlag {
    std::string flag_id;
    std::string transaction_id;
    double risk_score = 0.0;
    std::string risk_level; // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    std::vector<std::string> reasons;
    std::string explanation_title;
    std::string recommended_action;
    std::string created_at;

    nlohmann::json to_json() const {
        return {
            {"flag_id", flag_id},
            {"transaction_id", transaction_id},
            {"risk_score", risk_score},
            {"risk_level", risk_level},
            {"explanation_title", explanation_title},
            {"warning_reasons", reasons},
            {"recommended_action", recommended_action},
            {"created_at", created_at}
        };
    }
};

} // namespace onyx::models
