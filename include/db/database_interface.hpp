#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include "models/user.hpp"
#include "models/account.hpp"
#include "models/transaction.hpp"
#include "models/flag.hpp"
#include "models/complaint.hpp"
#include "models/ground_truth.hpp"

namespace trustgraph::db {

struct TransferResult {
    bool success = false;
    std::string error_message;
    models::Transaction transaction;
    std::optional<models::TransactionFlag> flag;
};

class IDatabase {
public:
    virtual ~IDatabase() = default;

    // User Operations
    virtual std::optional<models::User> find_user_by_username(const std::string& username) = 0;
    virtual std::optional<models::User> find_user_by_id(const std::string& user_id) = 0;
    virtual std::optional<models::User> find_user_by_account_id(const std::string& account_id) = 0;
    virtual bool create_user(const models::User& user) = 0;
    virtual bool update_user(const models::User& user) = 0;
    virtual std::vector<models::User> list_users() = 0;

    // Account Operations
    virtual std::optional<models::Account> find_account_by_id(const std::string& account_id) = 0;
    virtual std::optional<models::Account> find_account_by_upi(const std::string& upi_id) = 0;
    virtual bool create_account(const models::Account& account) = 0;
    virtual bool update_account(const models::Account& account) = 0;
    virtual bool update_account_status(const std::string& account_id, models::AccountStatus status) = 0;
    virtual std::vector<models::Account> list_accounts() = 0;

    // Transaction & Atomic Ledger Operations
    virtual std::optional<models::Transaction> find_transaction_by_id(const std::string& transaction_id) = 0;
    virtual bool create_transaction(const models::Transaction& tx) = 0;
    virtual bool update_transaction(const models::Transaction& tx) = 0;
    virtual std::vector<models::Transaction> list_transactions() = 0;
    virtual std::vector<models::Transaction> find_transactions_by_account(const std::string& account_id) = 0;
    virtual TransferResult execute_atomic_transfer(
        const std::string& sender_id,
        const std::string& receiver_id,
        double amount,
        models::TransactionStatus status,
        const std::optional<models::TransactionFlag>& flag = std::nullopt) = 0;

    // Flag Operations
    virtual std::optional<models::TransactionFlag> find_flag_by_transaction_id(const std::string& transaction_id) = 0;
    virtual bool create_flag(const models::TransactionFlag& flag) = 0;

    // Fraud Complaint Operations
    virtual std::optional<models::FraudComplaint> find_complaint_by_id(const std::string& complaint_id) = 0;
    virtual bool create_complaint(const models::FraudComplaint& complaint) = 0;
    virtual std::vector<models::FraudComplaint> list_complaints(const std::optional<std::string>& status = std::nullopt, size_t limit = 50) = 0;
    virtual size_t count_complaints_for_suspect(const std::string& suspect_account_id) = 0;
    virtual bool update_complaint_status(const std::string& complaint_id, const std::string& status) = 0;
    virtual bool apply_taint_update(const std::string& suspect_account_id, double risk_score_delta, models::AccountStatus new_status) = 0;

    // Ground Truth & Dataset Loading Operations
    virtual bool load_from_database_dir(const std::string& db_dir) = 0;
    virtual std::vector<models::GroundTruthScenario> list_ground_truth_scenarios() = 0;
    virtual std::optional<models::GroundTruthAccount> find_ground_truth_account(const std::string& account_id) = 0;

    // Seeding & Lifecycle
    virtual void seed_default_data() = 0;
    virtual void clear() = 0;
};

using DatabasePtr = std::shared_ptr<IDatabase>;

} // namespace trustgraph::db
