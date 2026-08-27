#pragma once

#include "db/database_interface.hpp"
#include <unordered_map>
#include <shared_mutex>
#include <mutex>

namespace onyx::db {

class InMemoryStore : public IDatabase {
public:
    InMemoryStore();
    ~InMemoryStore() override = default;

    // User Operations
    std::optional<models::User> find_user_by_username(const std::string& username) override;
    std::optional<models::User> find_user_by_id(const std::string& user_id) override;
    std::optional<models::User> find_user_by_account_id(const std::string& account_id) override;
    bool create_user(const models::User& user) override;
    bool update_user(const models::User& user) override;
    std::vector<models::User> list_users() override;

    // Account Operations
    std::optional<models::Account> find_account_by_id(const std::string& account_id) override;
    std::optional<models::Account> find_account_by_upi(const std::string& upi_id) override;
    bool create_account(const models::Account& account) override;
    bool update_account(const models::Account& account) override;
    bool update_account_status(const std::string& account_id, models::AccountStatus status) override;
    std::vector<models::Account> list_accounts() override;

    // Transaction Operations
    std::optional<models::Transaction> find_transaction_by_id(const std::string& transaction_id) override;
    bool create_transaction(const models::Transaction& tx) override;
    bool update_transaction(const models::Transaction& tx) override;
    std::vector<models::Transaction> list_transactions() override;
    std::vector<models::Transaction> find_transactions_by_account(const std::string& account_id) override;
    TransferResult execute_atomic_transfer(
        const std::string& sender_id,
        const std::string& receiver_id,
        double amount,
        models::TransactionStatus status,
        const std::optional<models::TransactionFlag>& flag = std::nullopt) override;

    // Flag Operations
    std::optional<models::TransactionFlag> find_flag_by_transaction_id(const std::string& transaction_id) override;
    bool create_flag(const models::TransactionFlag& flag) override;

    // Fraud Complaint Operations
    std::optional<models::FraudComplaint> find_complaint_by_id(const std::string& complaint_id) override;
    bool create_complaint(const models::FraudComplaint& complaint) override;
    std::vector<models::FraudComplaint> list_complaints(const std::optional<std::string>& status = std::nullopt, size_t limit = 50) override;
    size_t count_complaints_for_suspect(const std::string& suspect_account_id) override;
    bool update_complaint_status(const std::string& complaint_id, const std::string& status) override;
    bool apply_taint_update(const std::string& suspect_account_id, double risk_score_delta, models::AccountStatus new_status) override;

    // Ground Truth & Dataset Loading Operations
    bool load_from_database_dir(const std::string& db_dir) override;
    std::vector<models::GroundTruthScenario> list_ground_truth_scenarios() override;
    std::optional<models::GroundTruthAccount> find_ground_truth_account(const std::string& account_id) override;

    // Seeding & Lifecycle
    void seed_default_data() override;
    void clear() override;

private:
    mutable std::shared_mutex mutex_;

    // Primary tables
    std::unordered_map<std::string, models::User> users_by_id_;
    std::unordered_map<std::string, std::string> user_id_by_username_;

    std::unordered_map<std::string, models::Account> accounts_by_id_;
    std::unordered_map<std::string, std::string> account_id_by_upi_;

    std::unordered_map<std::string, models::Transaction> transactions_by_id_;
    std::unordered_map<std::string, std::vector<std::string>> account_tx_index_; // O(1) inverted index
    std::unordered_map<std::string, models::TransactionFlag> flags_by_tx_id_;

    std::unordered_map<std::string, models::FraudComplaint> complaints_by_id_;
    std::vector<std::string> complaint_order_;

    // Ground Truth evaluation tables
    std::unordered_map<std::string, models::GroundTruthAccount> gt_accounts_by_id_;
    std::vector<models::GroundTruthScenario> gt_scenarios_;
};

} // namespace onyx::db
