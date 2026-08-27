#include "db/in_memory_store.hpp"
#include "auth/password_hasher.hpp"
#include "utils/crypto_utils.hpp"
#include "utils/json.hpp"
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <fstream>

namespace trustgraph::db {

namespace {
std::string get_current_iso_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}
} // anonymous namespace

InMemoryStore::InMemoryStore() {
    seed_default_data();
}

void InMemoryStore::clear() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    users_by_id_.clear();
    user_id_by_username_.clear();
    accounts_by_id_.clear();
    account_id_by_upi_.clear();
    transactions_by_id_.clear();
    account_tx_index_.clear();
    flags_by_tx_id_.clear();
    complaints_by_id_.clear();
    complaint_order_.clear();
    gt_accounts_by_id_.clear();
    gt_scenarios_.clear();
}

void InMemoryStore::seed_default_data() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    users_by_id_.clear();
    user_id_by_username_.clear();
    accounts_by_id_.clear();
    account_id_by_upi_.clear();
    transactions_by_id_.clear();
    account_tx_index_.clear();
    flags_by_tx_id_.clear();
    complaints_by_id_.clear();
    complaint_order_.clear();
    gt_accounts_by_id_.clear();
    gt_scenarios_.clear();

    std::string timestamp = get_current_iso_timestamp();

    // 1. Seed Accounts
    models::Account acc1;
    acc1.account_id = "ACC-7A1B8C9D";
    acc1.upi_id = "siddharth@okaxis";
    acc1.holder_name = "Siddharth Kumar";
    acc1.balance = 150000.00;
    acc1.risk_score = 5.0;
    acc1.status = models::AccountStatus::ACTIVE;
    acc1.created_at = timestamp;
    accounts_by_id_[acc1.account_id] = acc1;
    account_id_by_upi_[acc1.upi_id] = acc1.account_id;

    models::Account acc2;
    acc2.account_id = "ACC-9F2E4A10";
    acc2.upi_id = "invest_guru@ybl";
    acc2.holder_name = "Invest Guru Operations";
    acc2.balance = 45000.00;
    acc2.risk_score = 88.5;
    acc2.status = models::AccountStatus::FLAGGED;
    acc2.created_at = timestamp;
    accounts_by_id_[acc2.account_id] = acc2;
    account_id_by_upi_[acc2.upi_id] = acc2.account_id;

    models::Account acc3;
    acc3.account_id = "ACC-3B8C1D9E";
    acc3.upi_id = "mule_wallet@paytm";
    acc3.holder_name = "Fast Cash Payout Node";
    acc3.balance = 92000.00;
    acc3.risk_score = 92.0;
    acc3.status = models::AccountStatus::FLAGGED;
    acc3.created_at = timestamp;
    accounts_by_id_[acc3.account_id] = acc3;
    account_id_by_upi_[acc3.upi_id] = acc3.account_id;

    // 2. Seed Users (With cryptographically hashed passwords using PBKDF2)
    models::User u1;
    u1.user_id = "USR-8819A";
    u1.username = "siddharth_k";
    u1.name = "Siddharth Kumar";
    u1.password_hash = auth::PasswordHasher::hash_password("secure_password_123", 10000); // 10k rounds for fast seeding
    u1.role = models::UserRole::CONSUMER;
    u1.associated_account_id = "ACC-7A1B8C9D";
    u1.created_at = timestamp;
    users_by_id_[u1.user_id] = u1;
    user_id_by_username_[u1.username] = u1.user_id;

    models::User u2;
    u2.user_id = "USR-BANK-001";
    u2.username = "analyst_raj";
    u2.name = "Rajesh Sharma";
    u2.password_hash = auth::PasswordHasher::hash_password("bank_employee_pass_456", 10000);
    u2.role = models::UserRole::BANK_EMPLOYEE;
    u2.associated_account_id = std::nullopt;
    u2.created_at = timestamp;
    users_by_id_[u2.user_id] = u2;
    user_id_by_username_[u2.username] = u2.user_id;

    models::User u3;
    u3.user_id = "USR-BANK-002";
    u3.username = "officer_priya";
    u3.name = "Priya Nair";
    u3.password_hash = auth::PasswordHasher::hash_password("admin_investigator_789", 10000);
    u3.role = models::UserRole::BANK_EMPLOYEE;
    u3.associated_account_id = std::nullopt;
    u3.created_at = timestamp;
    users_by_id_[u3.user_id] = u3;
    user_id_by_username_[u3.username] = u3.user_id;

    // 3. Seed Transactions
    models::Transaction tx1;
    tx1.transaction_id = "TXN-88F19280AA";
    tx1.sender_account_id = "ACC-7A1B8C9D";
    tx1.receiver_account_id = "ACC-9F2E4A10";
    tx1.amount = 45000.00;
    tx1.status = models::TransactionStatus::HELD;
    tx1.timestamp = timestamp;
    transactions_by_id_[tx1.transaction_id] = tx1;
    account_tx_index_[tx1.sender_account_id].push_back(tx1.transaction_id);
    account_tx_index_[tx1.receiver_account_id].push_back(tx1.transaction_id);

    // 4. Seed Transaction Flags
    models::TransactionFlag flag1;
    flag1.flag_id = "FLG-2026-901";
    flag1.transaction_id = "TXN-88F19280AA";
    flag1.risk_score = 88.5;
    flag1.risk_level = "CRITICAL";
    flag1.explanation_title = "High Velocity Mule Pass-Through Detected";
    flag1.reasons = {
        "Recipient account created less than 4 days ago.",
        "Abnormal Inflow: Recipient received deposits from 9 distinct UPI accounts in the last 30 minutes.",
        "Rapid Drain Velocity: 94% of accumulated funds were transferred onward within 8 minutes of arrival."
    };
    flag1.recommended_action = "Do not approve or send additional funds. Report this transaction if unsolicited.";
    flag1.created_at = timestamp;
    flags_by_tx_id_[flag1.transaction_id] = flag1;
}

// User Operations
std::optional<models::User> InMemoryStore::find_user_by_username(const std::string& username) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = user_id_by_username_.find(username);
    if (it != user_id_by_username_.end()) {
        auto u_it = users_by_id_.find(it->second);
        if (u_it != users_by_id_.end()) {
            return u_it->second;
        }
    }
    return std::nullopt;
}

std::optional<models::User> InMemoryStore::find_user_by_id(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = users_by_id_.find(user_id);
    if (it != users_by_id_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<models::User> InMemoryStore::find_user_by_account_id(const std::string& account_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (const auto& [_, u] : users_by_id_) {
        if (u.associated_account_id.has_value() && *u.associated_account_id == account_id) {
            return u;
        }
    }
    return std::nullopt;
}

bool InMemoryStore::create_user(const models::User& user) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (user_id_by_username_.find(user.username) != user_id_by_username_.end()) {
        return false; // Duplicate username
    }
    users_by_id_[user.user_id] = user;
    user_id_by_username_[user.username] = user.user_id;
    return true;
}

bool InMemoryStore::update_user(const models::User& user) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = users_by_id_.find(user.user_id);
    if (it == users_by_id_.end()) {
        return false;
    }
    it->second = user;
    return true;
}

std::vector<models::User> InMemoryStore::list_users() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<models::User> list;
    list.reserve(users_by_id_.size());
    for (const auto& [_, u] : users_by_id_) {
        list.push_back(u);
    }
    return list;
}

// Account Operations
std::optional<models::Account> InMemoryStore::find_account_by_id(const std::string& account_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = accounts_by_id_.find(account_id);
    if (it != accounts_by_id_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<models::Account> InMemoryStore::find_account_by_upi(const std::string& upi_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = account_id_by_upi_.find(upi_id);
    if (it != account_id_by_upi_.end()) {
        auto a_it = accounts_by_id_.find(it->second);
        if (a_it != accounts_by_id_.end()) {
            return a_it->second;
        }
    }
    return std::nullopt;
}

bool InMemoryStore::create_account(const models::Account& account) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (account_id_by_upi_.find(account.upi_id) != account_id_by_upi_.end()) {
        return false;
    }
    accounts_by_id_[account.account_id] = account;
    account_id_by_upi_[account.upi_id] = account.account_id;
    return true;
}

bool InMemoryStore::update_account(const models::Account& account) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = accounts_by_id_.find(account.account_id);
    if (it == accounts_by_id_.end()) {
        return false;
    }
    it->second = account;
    return true;
}

bool InMemoryStore::update_account_status(const std::string& account_id, models::AccountStatus status) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = accounts_by_id_.find(account_id);
    if (it == accounts_by_id_.end()) {
        return false;
    }
    it->second.status = status;
    return true;
}

std::vector<models::Account> InMemoryStore::list_accounts() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<models::Account> list;
    list.reserve(accounts_by_id_.size());
    for (const auto& [_, acc] : accounts_by_id_) {
        list.push_back(acc);
    }
    return list;
}

// Transaction Operations
std::optional<models::Transaction> InMemoryStore::find_transaction_by_id(const std::string& transaction_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = transactions_by_id_.find(transaction_id);
    if (it != transactions_by_id_.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool InMemoryStore::create_transaction(const models::Transaction& tx) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    transactions_by_id_[tx.transaction_id] = tx;
    account_tx_index_[tx.sender_account_id].push_back(tx.transaction_id);
    account_tx_index_[tx.receiver_account_id].push_back(tx.transaction_id);
    return true;
}

bool InMemoryStore::update_transaction(const models::Transaction& tx) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = transactions_by_id_.find(tx.transaction_id);
    if (it == transactions_by_id_.end()) {
        return false;
    }
    it->second = tx;
    return true;
}

std::vector<models::Transaction> InMemoryStore::list_transactions() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<models::Transaction> list;
    list.reserve(transactions_by_id_.size());
    for (const auto& [_, tx] : transactions_by_id_) {
        list.push_back(tx);
    }
    return list;
}

std::vector<models::Transaction> InMemoryStore::find_transactions_by_account(const std::string& account_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<models::Transaction> list;
    auto it = account_tx_index_.find(account_id);
    if (it != account_tx_index_.end()) {
        list.reserve(it->second.size());
        for (const auto& tid : it->second) {
            auto tx_it = transactions_by_id_.find(tid);
            if (tx_it != transactions_by_id_.end()) {
                list.push_back(tx_it->second);
            }
        }
    }
    return list;
}

TransferResult InMemoryStore::execute_atomic_transfer(
    const std::string& sender_id,
    const std::string& receiver_id,
    double amount,
    models::TransactionStatus status,
    const std::optional<models::TransactionFlag>& flag)
{
    TransferResult result;

    if (amount <= 0.0) {
        result.success = false;
        result.error_message = "Transfer amount must be strictly greater than 0.00";
        return result;
    }

    if (sender_id == receiver_id) {
        result.success = false;
        result.error_message = "Cannot transfer funds to the same account";
        return result;
    }

    // Deadlock-free sorted acquisition order guarantee: min(acc_a, acc_b) then max(acc_a, acc_b)
    const std::string& first_acc = std::min(sender_id, receiver_id);
    const std::string& second_acc = std::max(sender_id, receiver_id);
    (void)first_acc;
    (void)second_acc;

    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto s_it = accounts_by_id_.find(sender_id);
    if (s_it == accounts_by_id_.end()) {
        result.success = false;
        result.error_message = "Sender account not found: " + sender_id;
        return result;
    }

    auto r_it = accounts_by_id_.find(receiver_id);
    if (r_it == accounts_by_id_.end()) {
        result.success = false;
        result.error_message = "Receiver account not found: " + receiver_id;
        return result;
    }

    if (s_it->second.status == models::AccountStatus::FROZEN) {
        result.success = false;
        result.error_message = "Sender account is FROZEN. All outgoing transfers are blocked.";
        return result;
    }

    if (r_it->second.status == models::AccountStatus::FROZEN) {
        result.success = false;
        result.error_message = "Receiver account is FROZEN. Destination cannot accept transfers.";
        return result;
    }

    // Exact integer cents/paise arithmetic (prevents IEEE 754 precision drift)
    auto to_cents = [](double val) -> int64_t {
        return static_cast<int64_t>(std::llround(val * 100.0));
    };
    auto from_cents = [](int64_t cents) -> double {
        return static_cast<double>(cents) / 100.0;
    };

    int64_t amount_cents = to_cents(amount);
    int64_t sender_balance_cents = to_cents(s_it->second.balance);

    if (sender_balance_cents < amount_cents) {
        result.success = false;
        result.error_message = "Insufficient account balance for transfer.";
        return result;
    }

    // Atomic Balance Update with exact cents conversion
    if (status == models::TransactionStatus::COMPLETED) {
        int64_t receiver_balance_cents = to_cents(r_it->second.balance);
        s_it->second.balance = from_cents(sender_balance_cents - amount_cents);
        r_it->second.balance = from_cents(receiver_balance_cents + amount_cents);
    } else if (status == models::TransactionStatus::HELD) {
        // Debit sender, hold funds in escrow pending fraud resolution
        s_it->second.balance = from_cents(sender_balance_cents - amount_cents);
    }

    std::string timestamp = get_current_iso_timestamp();
    std::string tx_id = "TXN-" + crypto::get_random_hex(6);
    std::transform(tx_id.begin(), tx_id.end(), tx_id.begin(), ::toupper);

    models::Transaction tx;
    tx.transaction_id = tx_id;
    tx.sender_account_id = sender_id;
    tx.receiver_account_id = receiver_id;
    tx.amount = amount;
    tx.status = status;
    tx.timestamp = timestamp;

    transactions_by_id_[tx.transaction_id] = tx;
    account_tx_index_[tx.sender_account_id].push_back(tx.transaction_id);
    account_tx_index_[tx.receiver_account_id].push_back(tx.transaction_id);
    result.transaction = tx;

    if (flag.has_value()) {
        models::TransactionFlag f = *flag;
        if (f.flag_id.empty()) {
            f.flag_id = "FLG-" + crypto::get_random_hex(4);
            std::transform(f.flag_id.begin(), f.flag_id.end(), f.flag_id.begin(), ::toupper);
        }
        f.transaction_id = tx_id;
        f.created_at = timestamp;
        flags_by_tx_id_[tx_id] = f;
        result.flag = f;
    }

    result.success = true;
    return result;
}

// Flag Operations
std::optional<models::TransactionFlag> InMemoryStore::find_flag_by_transaction_id(const std::string& transaction_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = flags_by_tx_id_.find(transaction_id);
    if (it != flags_by_tx_id_.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool InMemoryStore::create_flag(const models::TransactionFlag& flag) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    flags_by_tx_id_[flag.transaction_id] = flag;
    return true;
}

// Fraud Complaint Operations
std::optional<models::FraudComplaint> InMemoryStore::find_complaint_by_id(const std::string& complaint_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = complaints_by_id_.find(complaint_id);
    if (it != complaints_by_id_.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool InMemoryStore::create_complaint(const models::FraudComplaint& complaint) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    complaints_by_id_[complaint.complaint_id] = complaint;
    complaint_order_.push_back(complaint.complaint_id);
    return true;
}

std::vector<models::FraudComplaint> InMemoryStore::list_complaints(const std::optional<std::string>& status, size_t limit) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<models::FraudComplaint> result;
    for (const auto& id : complaint_order_) {
        auto it = complaints_by_id_.find(id);
        if (it != complaints_by_id_.end()) {
            if (!status.has_value() || it->second.status == *status) {
                result.push_back(it->second);
                if (result.size() >= limit) break;
            }
        }
    }
    return result;
}

size_t InMemoryStore::count_complaints_for_suspect(const std::string& suspect_account_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [_, c] : complaints_by_id_) {
        if (c.suspect_account_id == suspect_account_id && c.status != "REJECTED") {
            count++;
        }
    }
    return count;
}

bool InMemoryStore::update_complaint_status(const std::string& complaint_id, const std::string& status) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = complaints_by_id_.find(complaint_id);
    if (it == complaints_by_id_.end()) {
        return false;
    }
    it->second.status = status;
    return true;
}

bool InMemoryStore::apply_taint_update(const std::string& suspect_account_id, double risk_score_delta, models::AccountStatus new_status) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = accounts_by_id_.find(suspect_account_id);
    if (it == accounts_by_id_.end()) {
        return false;
    }
    it->second.risk_score = std::min(100.0, std::max(0.0, it->second.risk_score + risk_score_delta));
    it->second.status = new_status;
    return true;
}

bool InMemoryStore::load_from_database_dir(const std::string& db_dir) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    // Attempt to locate 3.json which contains the clean benchmark dataset
    std::string json_path = db_dir + "/3.json";
    std::ifstream f(json_path);
    if (!f.is_open()) {
        if (db_dir != "databases") {
            f.open("databases/3.json");
        }
    }
    if (!f.is_open()) {
        f.open("../databases/3.json");
    }
    if (!f.is_open()) {
        return false;
    }

    try {
        nlohmann::json d = nlohmann::json::parse(f);

        // Precompute default password hash once (PBKDF2 10k rounds)
        static const std::string default_user_pwd_hash = auth::PasswordHasher::hash_password("password123", 10000);

        // 1. Ingest Accounts
        if (d.contains("accounts") && d["accounts"].is_array()) {
            for (const auto& a : d["accounts"]) {
                models::Account acc;
                acc.account_id = a.value("account_id", "");
                acc.upi_id = a.value("upi_id", "");
                acc.holder_name = a.value("customer_name", a.value("holder_name", ""));
                acc.account_type = a.value("account_type", "SAVINGS");
                acc.is_verified_merchant = a.value("is_verified_merchant", false);
                double raw_risk = a.value("risk_score", 0.0);
                if (raw_risk > 0.0 && raw_risk <= 1.0) {
                    raw_risk *= 100.0;
                }
                acc.risk_score = raw_risk;
                acc.status = models::string_to_account_status(a.value("status", "ACTIVE"));
                acc.created_at = a.value("created_at", "");

                if (!acc.account_id.empty()) {
                    accounts_by_id_[acc.account_id] = acc;
                    if (!acc.upi_id.empty()) {
                        account_id_by_upi_[acc.upi_id] = acc.account_id;
                    }

                    // Auto-seed consumer user account for RBAC login
                    std::string username = acc.upi_id;
                    if (user_id_by_username_.find(username) == user_id_by_username_.end()) {
                        models::User u;
                        u.user_id = "USR-" + acc.account_id;
                        u.username = username;
                        u.password_hash = default_user_pwd_hash;
                        u.role = models::UserRole::CONSUMER;
                        u.associated_account_id = acc.account_id;
                        u.created_at = acc.created_at;

                        users_by_id_[u.user_id] = u;
                        user_id_by_username_[u.username] = u.user_id;
                    }
                }
            }
        }

        // 2. Ingest Transactions
        if (d.contains("transactions") && d["transactions"].is_array()) {
            for (const auto& t : d["transactions"]) {
                models::Transaction tx;
                tx.transaction_id = t.value("transaction_id", "");
                tx.sender_account_id = t.value("sender_account_id", "");
                tx.receiver_account_id = t.value("receiver_account_id", "");
                tx.amount = t.value("amount", 0.0);
                tx.transaction_type = t.value("transaction_type", "UPI");
                tx.status = models::string_to_transaction_status(t.value("status", "SUCCESS"));
                tx.timestamp = t.value("timestamp", "");

                if (!tx.transaction_id.empty()) {
                    transactions_by_id_[tx.transaction_id] = tx;
                    account_tx_index_[tx.sender_account_id].push_back(tx.transaction_id);
                    account_tx_index_[tx.receiver_account_id].push_back(tx.transaction_id);
                }
            }
        }

        // 3. Ingest Ground Truth Accounts
        if (d.contains("ground_truth_accounts") && d["ground_truth_accounts"].is_array()) {
            for (const auto& g : d["ground_truth_accounts"]) {
                models::GroundTruthAccount gt;
                gt.account_id = g.value("account_id", "");
                gt.archetype = g.value("archetype", "");
                gt.is_fraud = g.value("is_fraud", false);
                if (!gt.account_id.empty()) {
                    gt_accounts_by_id_[gt.account_id] = gt;
                }
            }
        }

        // 4. Ingest Ground Truth Scenarios
        if (d.contains("ground_truth_scenarios") && d["ground_truth_scenarios"].is_array()) {
            gt_scenarios_.clear();
            for (const auto& s : d["ground_truth_scenarios"]) {
                models::GroundTruthScenario sc;
                sc.scenario_id = s.value("scenario_id", "");
                sc.typology = s.value("typology", "");
                sc.root_source_id = s.value("root_source_id", "");
                sc.total_stolen_amount = s.value("total_stolen_amount", 0.0);
                sc.start_time = s.value("start_time", "");
                sc.end_time = s.value("end_time", "");
                gt_scenarios_.push_back(sc);
            }
        }

        return true;
    } catch (...) {
        return false;
    }
}

std::vector<models::GroundTruthScenario> InMemoryStore::list_ground_truth_scenarios() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return gt_scenarios_;
}

std::optional<models::GroundTruthAccount> InMemoryStore::find_ground_truth_account(const std::string& account_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = gt_accounts_by_id_.find(account_id);
    if (it != gt_accounts_by_id_.end()) {
        return it->second;
    }
    return std::nullopt;
}

} // namespace trustgraph::db
