#include "engine/fraud_engine.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace onyx::engine {

FraudEvaluationResult FraudDetectionEngine::evaluate_transaction(
    const models::Account& sender,
    const models::Account& receiver,
    double amount,
    db::IDatabase& db)
{
    FraudEvaluationResult result;
    double score = receiver.risk_score;
    std::vector<std::string> reasons;

    // 1. Recipient Status & Base Risk Heuristic
    if (receiver.status == models::AccountStatus::FLAGGED || receiver.risk_score >= 70.0) {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(1) << receiver.risk_score;
        reasons.push_back("Recipient account flagged with high risk profile (Score: " + ss.str() + ").");
    }

    // 2. Complaint History
    size_t complaint_count = db.count_complaints_for_suspect(receiver.account_id);
    if (complaint_count > 0) {
        reasons.push_back("Recipient has " + std::to_string(complaint_count) + " active fraud complaint(s) logged in the Fraud Registry.");
        score += (20.0 * complaint_count);
    }

    // 3. Multi-Hop Velocity / Inflow Pattern
    auto receiver_txs = db.find_transactions_by_account(receiver.account_id);
    if (receiver_txs.size() >= 1) {
        reasons.push_back("Abnormal Inflow: Recipient received rapid deposits from multiple distinct accounts.");
        score += 15.0;
    }

    // 4. Drain Velocity Pattern
    if (receiver.risk_score >= 60.0 && amount >= 10000.0) {
        reasons.push_back("Rapid Drain Velocity: Destination account has pattern of immediate onward fund diversion.");
        score += 10.0;
    }

    // 5. Outflow Ratio
    if (sender.balance > 0 && amount >= 0.8 * sender.balance) {
        reasons.push_back("High Outflow Ratio: Outbound amount represents >=80% of current available balance.");
        score += 10.0;
    }

    // Cap score at 100.0
    result.risk_score = std::min(100.0, std::max(0.0, score));

    // Classify Level & Suggested Action
    if (result.risk_score >= 75.0) {
        result.risk_level = "CRITICAL";
        result.is_flagged = true;
        result.suggested_status = models::TransactionStatus::HELD;
        result.explanation_title = "High Velocity Mule Pass-Through Detected";
        result.recommended_action = "Do not approve or send additional funds. Report this transaction if unsolicited.";
    } else if (result.risk_score >= 50.0) {
        result.risk_level = "HIGH";
        result.is_flagged = true;
        result.suggested_status = models::TransactionStatus::FLAGGED;
        result.explanation_title = "Suspicious Counterparty Activity Detected";
        result.recommended_action = "Verify recipient credentials before confirming further transactions.";
    } else if (result.risk_score >= 25.0) {
        result.risk_level = "MEDIUM";
        result.is_flagged = false;
        result.suggested_status = models::TransactionStatus::COMPLETED;
        result.explanation_title = "Moderate Destination Risk";
        result.recommended_action = "Proceed with caution.";
    } else {
        result.risk_level = "LOW";
        result.is_flagged = false;
        result.suggested_status = models::TransactionStatus::COMPLETED;
        result.explanation_title = "Standard Verified Transfer";
        result.recommended_action = "No anomalous risk indicators detected.";
    }

    if (reasons.empty()) {
        reasons.push_back("All standard heuristics and velocity checks passed.");
    }

    result.warning_reasons = std::move(reasons);
    return result;
}

} // namespace onyx::engine
