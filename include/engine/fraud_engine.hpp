#pragma once

#include <string>
#include <vector>
#include <optional>
#include "models/account.hpp"
#include "models/transaction.hpp"
#include "models/flag.hpp"
#include "db/database_interface.hpp"

namespace trustgraph::engine {

struct FraudEvaluationResult {
    double risk_score = 0.0;
    std::string risk_level = "LOW"; // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    bool is_flagged = false;
    models::TransactionStatus suggested_status = models::TransactionStatus::COMPLETED;
    std::string explanation_title;
    std::vector<std::string> warning_reasons;
    std::string recommended_action;
};

class FraudDetectionEngine {
public:
    FraudDetectionEngine() = default;

    // Evaluates risk indicators for an outbound transfer
    static FraudEvaluationResult evaluate_transaction(
        const models::Account& sender,
        const models::Account& receiver,
        double amount,
        db::IDatabase& db);
};

} // namespace trustgraph::engine
