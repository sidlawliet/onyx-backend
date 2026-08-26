#include <iostream>
#include <memory>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

#include "utils/logger.hpp"
#include "utils/json.hpp"
#include "db/in_memory_store.hpp"
#include "auth/password_hasher.hpp"
#include "auth/jwt_manager.hpp"
#include "auth/rbac_middleware.hpp"
#include "server/http_server.hpp"
#include "server/router.hpp"
#include "engine/fraud_engine.hpp"
#include "engine/graph_engine.hpp"
#include "utils/crypto_utils.hpp"

using json = nlohmann::json;
using namespace trustgraph;

static std::atomic<bool> g_shutdown_requested{false};

void signal_handler(int) {
    g_shutdown_requested = true;
}

int main() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    utils::Logger::info("=================================================");
    utils::Logger::info("   TrustGraph Financial Fraud Engine (v1.2)     ");
    utils::Logger::info("   C++ High-Performance Backend Engine           ");
    utils::Logger::info("=================================================");

    // 1. Initialize Database & Link Dataset
    auto db = std::make_shared<db::InMemoryStore>();
    std::string db_dir = "databases";
    if (const char* env_dir = std::getenv("TRUSTGRAPH_DB_DIR")) {
        db_dir = env_dir;
    }
    if (db->load_from_database_dir(db_dir)) {
        utils::Logger::info("Linked TrustGraph Database from '" + db_dir + "': 1,000 accounts, 32,000 transactions, 5 scenarios active.");
    } else {
        utils::Logger::warn("Could not load database directory from '" + db_dir + "'; running with in-memory default fixtures.");
    }

    // 2. Initialize JWT Manager & RBAC Middleware
    std::string jwt_secret = "trustgraph_super_secret_jwt_key_2026_x99!@";
    auto jwt_manager = std::make_shared<auth::JwtManager>(jwt_secret, 86400);
    auto rbac_middleware = std::make_shared<auth::RbacMiddleware>(jwt_manager);

    // 3. Initialize Router
    auto router = std::make_shared<server::Router>(rbac_middleware);

    // Route: Health Check
    router->get("/api/v1/health", auth::RoleRequirement::PUBLIC, [](const server::HttpRequest&, const auth::AuthContext&) {
        json payload = {
            {"status", "HEALTHY"},
            {"service", "TrustGraph C++ Backend Engine"},
            {"version", "1.2.0"},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
        return server::HttpResponse::json(200, payload);
    });

    // Route: POST /api/v1/auth/login
    router->post("/api/v1/auth/login", auth::RoleRequirement::PUBLIC, [db, jwt_manager](const server::HttpRequest& req, const auth::AuthContext&) {
        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            return server::HttpResponse::error(400, "Bad Request", "Malformed JSON request body");
        }

        if (!body.contains("username") || !body["username"].is_string() ||
            !body.contains("password") || !body["password"].is_string() ||
            !body.contains("role") || !body["role"].is_string()) {
            return server::HttpResponse::error(400, "Bad Request", "Missing required fields: username, password, role");
        }

        std::string username = body["username"].get<std::string>();
        std::string password = body["password"].get<std::string>();
        std::string role_str = body["role"].get<std::string>();

        auto role_opt = models::string_to_user_role(role_str);
        if (!role_opt.has_value()) {
            return server::HttpResponse::error(400, "Bad Request", "Invalid role specified. Must be 'CONSUMER' or 'BANK_EMPLOYEE'");
        }

        auto user_opt = db->find_user_by_username(username);
        if (!user_opt.has_value() || user_opt->role != *role_opt) {
            return server::HttpResponse::error(401, "Unauthorized", "Invalid credentials or unauthorized role requested");
        }

        if (!auth::PasswordHasher::verify_password(password, user_opt->password_hash)) {
            return server::HttpResponse::error(401, "Unauthorized", "Invalid credentials");
        }

        // Generate JWT Token
        auth::JwtTokenClaims claims;
        claims.user_id = user_opt->user_id;
        claims.username = user_opt->username;
        claims.role = models::user_role_to_string(user_opt->role);
        claims.associated_account_id = user_opt->associated_account_id;
        claims.iat = 0; // automatic now
        claims.exp = 0; // automatic now + 86400

        std::string token = jwt_manager->create_token(claims);

        json response_payload = {
            {"access_token", token},
            {"token_type", "Bearer"},
            {"expires_in", jwt_manager->get_default_expiry_seconds()},
            {"user", user_opt->to_json_public()}
        };

        utils::Logger::info("User logged in successfully: " + username + " (Role: " + role_str + ")");
        return server::HttpResponse::json(200, response_payload);
    });

    // Route: GET /api/v1/auth/me (Protected: ANY_AUTHENTICATED)
    router->get("/api/v1/auth/me", auth::RoleRequirement::ANY_AUTHENTICATED, [db](const server::HttpRequest&, const auth::AuthContext& auth_ctx) {
        auto user_opt = db->find_user_by_id(auth_ctx.user_id);
        if (!user_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "User not found");
        }
        return server::HttpResponse::json(200, user_opt->to_json_public());
    });

    // Route: GET /api/v1/consumer/my-account (Protected: CONSUMER_ONLY)
    router->get("/api/v1/consumer/my-account", auth::RoleRequirement::CONSUMER_ONLY, [db](const server::HttpRequest&, const auth::AuthContext& auth_ctx) {
        if (!auth_ctx.associated_account_id.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "No account associated with this consumer profile");
        }
        auto account_opt = db->find_account_by_id(*auth_ctx.associated_account_id);
        if (!account_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Associated account record not found");
        }
        return server::HttpResponse::json(200, account_opt->to_json());
    });

    // Route: GET /api/v1/admin/audit-summary (Protected: BANK_EMPLOYEE_ONLY)
    router->get("/api/v1/admin/audit-summary", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [db](const server::HttpRequest&, const auth::AuthContext& auth_ctx) {
        auto users = db->list_users();
        auto accounts = db->list_accounts();
        auto txs = db->list_transactions();

        json summary = {
            {"requested_by", auth_ctx.username},
            {"total_users", users.size()},
            {"total_accounts", accounts.size()},
            {"total_transactions", txs.size()}
        };
        return server::HttpResponse::json(200, summary);
    });

    // Route: POST /api/v1/transactions (Protected: ANY_AUTHENTICATED)
    router->post("/api/v1/transactions", auth::RoleRequirement::ANY_AUTHENTICATED, [db](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            return server::HttpResponse::error(400, "Bad Request", "Malformed JSON request body");
        }

        double amount = 0.0;
        if (body.contains("amount") && body["amount"].is_number()) {
            amount = body["amount"].get<double>();
        } else {
            return server::HttpResponse::error(400, "Bad Request", "Missing or invalid 'amount' field");
        }

        if (amount <= 0.0) {
            return server::HttpResponse::error(400, "Bad Request", "Transfer amount must be strictly greater than 0.00");
        }

        // Determine Sender Account
        std::string sender_account_id;
        if (auth_ctx.is_consumer()) {
            if (!auth_ctx.associated_account_id.has_value() || auth_ctx.associated_account_id->empty()) {
                return server::HttpResponse::error(403, "Forbidden", "Consumer profile has no associated bank account");
            }
            sender_account_id = *auth_ctx.associated_account_id;
        } else {
            // Bank employee can specify sender_account_id
            if (body.contains("sender_account_id") && body["sender_account_id"].is_string()) {
                sender_account_id = body["sender_account_id"].get<std::string>();
            } else {
                return server::HttpResponse::error(400, "Bad Request", "Bank employee transfer requires 'sender_account_id'");
            }
        }

        // Determine Receiver Account
        std::optional<models::Account> receiver_acc_opt;
        if (body.contains("receiver_upi_id") && body["receiver_upi_id"].is_string()) {
            std::string receiver_upi = body["receiver_upi_id"].get<std::string>();
            receiver_acc_opt = db->find_account_by_upi(receiver_upi);
        } else if (body.contains("receiver_account_id") && body["receiver_account_id"].is_string()) {
            std::string receiver_acc_id = body["receiver_account_id"].get<std::string>();
            receiver_acc_opt = db->find_account_by_id(receiver_acc_id);
        } else {
            return server::HttpResponse::error(400, "Bad Request", "Missing recipient identifier ('receiver_upi_id' or 'receiver_account_id')");
        }

        if (!receiver_acc_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Recipient account or UPI ID not found in TrustGraph directory");
        }

        auto sender_acc_opt = db->find_account_by_id(sender_account_id);
        if (!sender_acc_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Sender account not found");
        }

        if (sender_acc_opt->account_id == receiver_acc_opt->account_id) {
            return server::HttpResponse::error(400, "Bad Request", "Cannot transfer funds to the same account");
        }

        // Run Real-Time Fraud Evaluation Heuristics
        auto eval = engine::FraudDetectionEngine::evaluate_transaction(*sender_acc_opt, *receiver_acc_opt, amount, *db);

        std::optional<models::TransactionFlag> flag_opt = std::nullopt;
        if (eval.is_flagged) {
            models::TransactionFlag flag;
            flag.risk_score = eval.risk_score;
            flag.risk_level = eval.risk_level;
            flag.reasons = eval.warning_reasons;
            flag.explanation_title = eval.explanation_title;
            flag.recommended_action = eval.recommended_action;
            flag_opt = flag;
        }

        // Execute Atomic Transfer
        auto transfer_res = db->execute_atomic_transfer(
            sender_acc_opt->account_id,
            receiver_acc_opt->account_id,
            amount,
            eval.suggested_status,
            flag_opt
        );

        if (!transfer_res.success) {
            return server::HttpResponse::error(400, "Transfer Failed", transfer_res.error_message);
        }

        json response_json = {
            {"transaction_id", transfer_res.transaction.transaction_id},
            {"sender_account_id", transfer_res.transaction.sender_account_id},
            {"receiver_account_id", transfer_res.transaction.receiver_account_id},
            {"amount", transfer_res.transaction.amount},
            {"status", models::transaction_status_to_string(transfer_res.transaction.status)},
            {"risk_score", eval.risk_score},
            {"risk_level", eval.risk_level},
            {"is_flagged", eval.is_flagged},
            {"timestamp", transfer_res.transaction.timestamp}
        };

        if (transfer_res.flag.has_value()) {
            response_json["flag_id"] = transfer_res.flag->flag_id;
            response_json["explanation_title"] = transfer_res.flag->explanation_title;
            response_json["warning_reasons"] = transfer_res.flag->reasons;
            response_json["recommended_action"] = transfer_res.flag->recommended_action;
        }

        utils::Logger::info("Transaction executed: " + transfer_res.transaction.transaction_id +
                            " | Amount: " + std::to_string(amount) +
                            " | Status: " + models::transaction_status_to_string(transfer_res.transaction.status) +
                            " | Risk Score: " + std::to_string(eval.risk_score));

        return server::HttpResponse::json(201, response_json);
    });

    // Route: GET /api/v1/transactions (Protected: ANY_AUTHENTICATED)
    router->get("/api/v1/transactions", auth::RoleRequirement::ANY_AUTHENTICATED, [db](const server::HttpRequest&, const auth::AuthContext& auth_ctx) {
        std::vector<models::Transaction> txs;
        if (auth_ctx.is_consumer()) {
            if (auth_ctx.associated_account_id.has_value()) {
                txs = db->find_transactions_by_account(*auth_ctx.associated_account_id);
            }
        } else {
            txs = db->list_transactions();
        }

        json tx_list = json::array();
        for (const auto& tx : txs) {
            json item = tx.to_json();
            auto flag_opt = db->find_flag_by_transaction_id(tx.transaction_id);
            if (flag_opt.has_value()) {
                item["flag"] = flag_opt->to_json();
            }
            tx_list.push_back(item);
        }

        return server::HttpResponse::json(200, {{"total", tx_list.size()}, {"transactions", tx_list}});
    });

    // Route: GET /api/v1/transactions/:transaction_id (Protected: ANY_AUTHENTICATED)
    router->get("/api/v1/transactions/:transaction_id", auth::RoleRequirement::ANY_AUTHENTICATED, [db](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
        std::string tx_id = req.path_params.at("transaction_id");
        auto tx_opt = db->find_transaction_by_id(tx_id);
        if (!tx_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Transaction not found: " + tx_id);
        }

        // Ownership authorization check for consumer
        if (auth_ctx.is_consumer()) {
            if (!auth_ctx.associated_account_id.has_value() ||
                (tx_opt->sender_account_id != *auth_ctx.associated_account_id &&
                 tx_opt->receiver_account_id != *auth_ctx.associated_account_id)) {
                return server::HttpResponse::error(403, "Forbidden", "Access denied: You do not have permission to view this transaction record");
            }
        }

        json res_json = tx_opt->to_json();
        auto flag_opt = db->find_flag_by_transaction_id(tx_id);
        if (flag_opt.has_value()) {
            res_json["flag"] = flag_opt->to_json();
        }

        return server::HttpResponse::json(200, res_json);
    });

    // Route: GET /api/v1/accounts/verify-risk/:upi_id (Protected: ANY_AUTHENTICATED)
    router->get("/api/v1/accounts/verify-risk/:upi_id", auth::RoleRequirement::ANY_AUTHENTICATED, [db](const server::HttpRequest& req, const auth::AuthContext&) {
        std::string upi_id = req.path_params.at("upi_id");
        auto acc_opt = db->find_account_by_upi(upi_id);
        if (!acc_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Recipient UPI ID not found in directory: " + upi_id);
        }

        const auto& acc = *acc_opt;
        std::vector<std::string> signals;
        bool is_safe = true;
        std::string risk_level = "LOW";
        std::string recommended_action = "Recipient is verified and low risk. Safe to proceed with payment.";

        if (acc.status == models::AccountStatus::FROZEN) {
            signals.push_back("Recipient account is FROZEN by Bank Security.");
            is_safe = false;
            risk_level = "CRITICAL";
            recommended_action = "Do not attempt payment. Recipient account is frozen due to fraud investigations.";
        } else if (acc.status == models::AccountStatus::FLAGGED || acc.risk_score >= 70.0) {
            signals.push_back("Recipient account is currently marked FLAGGED in Bank Fraud Intelligence.");
            is_safe = false;
            risk_level = "CRITICAL";
            recommended_action = "Do not send funds. Recipient exhibits strong money mule / fraud indicators.";
        } else if (acc.risk_score >= 40.0) {
            signals.push_back("Recipient account has elevated risk activity.");
            is_safe = false;
            risk_level = "HIGH";
            recommended_action = "Exercise caution. Confirm recipient identity before sending large amounts.";
        } else {
            signals.push_back("Recipient account has clean history and verified status.");
            signals.push_back("All standard heuristics and velocity checks passed.");
        }

        size_t complaints = db->count_complaints_for_suspect(acc.account_id);
        if (complaints > 0) {
            signals.push_back("Account has " + std::to_string(complaints) + " active scam/fraud complaint(s) filed by consumers.");
            is_safe = false;
            risk_level = "CRITICAL";
        }

        json response_json = {
            {"upi_id", acc.upi_id},
            {"account_id", acc.account_id},
            {"holder_name", acc.holder_name},
            {"risk_score", acc.risk_score},
            {"risk_level", risk_level},
            {"account_status", models::account_status_to_string(acc.status)},
            {"is_safe_to_pay", is_safe},
            {"signals", signals},
            {"recommended_action", recommended_action}
        };

        return server::HttpResponse::json(200, response_json);
    });

    // Route: GET /api/v1/transactions/:transaction_id/flag-details (Protected: ANY_AUTHENTICATED)
    router->get("/api/v1/transactions/:transaction_id/flag-details", auth::RoleRequirement::ANY_AUTHENTICATED, [db](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
        std::string tx_id = req.path_params.at("transaction_id");
        auto tx_opt = db->find_transaction_by_id(tx_id);
        if (!tx_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Transaction not found: " + tx_id);
        }

        // Ownership authorization check for consumer
        if (auth_ctx.is_consumer()) {
            if (!auth_ctx.associated_account_id.has_value() ||
                (tx_opt->sender_account_id != *auth_ctx.associated_account_id &&
                 tx_opt->receiver_account_id != *auth_ctx.associated_account_id)) {
                return server::HttpResponse::error(403, "Forbidden", "Access denied: You do not have permission to view flag details for this transaction");
            }
        }

        auto flag_opt = db->find_flag_by_transaction_id(tx_id);
        if (!flag_opt.has_value()) {
            // Clean transaction with no active flag
            json clean_response = {
                {"transaction_id", tx_opt->transaction_id},
                {"amount", tx_opt->amount},
                {"timestamp", tx_opt->timestamp},
                {"status", models::transaction_status_to_string(tx_opt->status)},
                {"risk_score", 0.0},
                {"risk_level", "LOW"},
                {"explanation_title", "Standard Clean Transfer"},
                {"warning_reasons", json::array({"Transaction passed all security heuristics with no anomaly detected."})},
                {"recommended_action", "Transaction verified safe."}
            };
            return server::HttpResponse::json(200, clean_response);
        }

        json flag_response = {
            {"transaction_id", tx_opt->transaction_id},
            {"amount", tx_opt->amount},
            {"timestamp", tx_opt->timestamp},
            {"status", models::transaction_status_to_string(tx_opt->status)},
            {"risk_score", flag_opt->risk_score},
            {"risk_level", flag_opt->risk_level},
            {"explanation_title", flag_opt->explanation_title},
            {"warning_reasons", flag_opt->reasons},
            {"recommended_action", flag_opt->recommended_action}
        };

        return server::HttpResponse::json(200, flag_response);
    });

    // Route: POST /api/v1/complaints (Protected: CONSUMER_ONLY)
    router->post("/api/v1/complaints", auth::RoleRequirement::CONSUMER_ONLY, [db](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
        if (!auth_ctx.associated_account_id.has_value() || auth_ctx.associated_account_id->empty()) {
            return server::HttpResponse::error(403, "Forbidden", "Consumer profile has no associated bank account");
        }

        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            return server::HttpResponse::error(400, "Bad Request", "Malformed JSON request body");
        }

        if (!body.contains("transaction_id") || !body["transaction_id"].is_string() ||
            !body.contains("suspect_upi_id") || !body["suspect_upi_id"].is_string() ||
            !body.contains("scam_category") || !body["scam_category"].is_string()) {
            return server::HttpResponse::error(400, "Bad Request", "Missing required fields: transaction_id, suspect_upi_id, scam_category");
        }

        std::string tx_id = body["transaction_id"].get<std::string>();
        std::string suspect_upi = body["suspect_upi_id"].get<std::string>();
        std::string scam_category = body["scam_category"].get<std::string>();
        std::string description = body.value("description", "");

        // 1. Verify transaction exists and complainant is sender
        auto tx_opt = db->find_transaction_by_id(tx_id);
        if (!tx_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Transaction record not found: " + tx_id);
        }

        if (tx_opt->sender_account_id != *auth_ctx.associated_account_id) {
            return server::HttpResponse::error(403, "Forbidden", "Access denied: You can only file complaints for outbound transfers from your own account");
        }

        // 2. Resolve suspect UPI ID
        auto suspect_acc_opt = db->find_account_by_upi(suspect_upi);
        if (!suspect_acc_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Suspect UPI ID not found in directory: " + suspect_upi);
        }

        if (suspect_acc_opt->account_id != tx_opt->receiver_account_id) {
            return server::HttpResponse::error(400, "Bad Request", "Suspect UPI ID does not match recipient of the transaction");
        }

        // 3. Create Fraud Complaint Record
        std::string cmp_id = "CMP-2026-" + crypto::get_random_hex(2);
        std::transform(cmp_id.begin(), cmp_id.end(), cmp_id.begin(), ::toupper);

        models::FraudComplaint complaint;
        complaint.complaint_id = cmp_id;
        complaint.complainant_account_id = *auth_ctx.associated_account_id;
        complaint.suspect_account_id = suspect_acc_opt->account_id;
        complaint.transaction_id = tx_opt->transaction_id;
        complaint.amount = tx_opt->amount;
        complaint.scam_category = scam_category;
        complaint.description = description;
        complaint.status = "SUBMITTED";
        complaint.created_at = tx_opt->timestamp;

        db->create_complaint(complaint);

        // 4. Graph Taint Feedback Loop
        size_t active_complaints = db->count_complaints_for_suspect(suspect_acc_opt->account_id);
        if (active_complaints >= 2) {
            db->apply_taint_update(suspect_acc_opt->account_id, 25.0, models::AccountStatus::FLAGGED);
            utils::Logger::warn("Taint feedback loop triggered: Suspect node " + suspect_acc_opt->account_id +
                                " has " + std::to_string(active_complaints) + " active complaints. Escalated risk (+25.0) and marked FLAGGED.");
        }

        json response_json = {
            {"complaint_id", complaint.complaint_id},
            {"status", complaint.status},
            {"message", "Complaint logged in Bank Fraud Registry. Taint score updated on recipient node."},
            {"timestamp", complaint.created_at}
        };

        return server::HttpResponse::json(201, response_json);
    });

    // Route: GET /api/v1/complaints (Protected: BANK_EMPLOYEE_ONLY)
    router->get("/api/v1/complaints", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [db](const server::HttpRequest& req, const auth::AuthContext&) {
        std::optional<std::string> status_filter = std::nullopt;
        auto it_status = req.query_params.find("status");
        if (it_status != req.query_params.end() && !it_status->second.empty()) {
            status_filter = it_status->second;
        }

        size_t limit = 50;
        auto it_limit = req.query_params.find("limit");
        if (it_limit != req.query_params.end() && !it_limit->second.empty()) {
            try {
                limit = std::stoul(it_limit->second);
            } catch (...) {
                limit = 50;
            }
        }

        auto complaints = db->list_complaints(status_filter, limit);
        json complaint_list = json::array();
        for (const auto& c : complaints) {
            complaint_list.push_back(c.to_json());
        }

        return server::HttpResponse::json(200, {
            {"total", complaint_list.size()},
            {"complaints", complaint_list}
        });
    });

    // Route: PUT /api/v1/complaints/:complaint_id/status (Protected: BANK_EMPLOYEE_ONLY)
    router->put("/api/v1/complaints/:complaint_id/status", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [db](const server::HttpRequest& req, const auth::AuthContext&) {
        std::string complaint_id = req.path_params.at("complaint_id");
        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            return server::HttpResponse::error(400, "Bad Request", "Malformed JSON request body");
        }

        if (!body.contains("status") || !body["status"].is_string()) {
            return server::HttpResponse::error(400, "Bad Request", "Missing 'status' field in request body");
        }

        std::string new_status = body["status"].get<std::string>();
        auto existing = db->find_complaint_by_id(complaint_id);
        if (!existing.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Complaint not found: " + complaint_id);
        }

        db->update_complaint_status(complaint_id, new_status);
        return server::HttpResponse::json(200, {
            {"complaint_id", complaint_id},
            {"status", new_status},
            {"message", "Complaint triage status updated successfully."}
        });
    });

    auto graph_engine = std::make_shared<engine::GraphEngine>(db);

    // Route: GET /api/v1/graph/subgraph/:account_id (Protected: ANY_AUTHENTICATED)
    router->get("/api/v1/graph/subgraph/:account_id", auth::RoleRequirement::ANY_AUTHENTICATED, [db, graph_engine](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
        std::string account_id = req.path_params.at("account_id");

        // Consumer privacy isolation: consumers can only extract subgraphs centered on their own account
        if (auth_ctx.is_consumer()) {
            if (!auth_ctx.associated_account_id.has_value()) {
                return server::HttpResponse::error(403, "Forbidden", "Consumer profile has no associated bank account");
            }
            auto target_acc = db->find_account_by_id(account_id);
            if (!target_acc.has_value()) {
                auto upi_acc = db->find_account_by_upi(account_id);
                if (upi_acc.has_value()) {
                    target_acc = upi_acc;
                }
            }
            if (!target_acc.has_value() || target_acc->account_id != *auth_ctx.associated_account_id) {
                return server::HttpResponse::error(403, "Forbidden", "Access denied: Consumers can only explore their own account subgraph");
            }
        }

        int depth = 2;
        auto it_depth = req.query_params.find("depth");
        if (it_depth != req.query_params.end() && !it_depth->second.empty()) {
            try {
                depth = std::stoi(it_depth->second);
            } catch (...) {
                depth = 2;
            }
        }
        depth = std::clamp(depth, 1, 5);

        size_t limit = 100;
        auto it_limit = req.query_params.find("limit");
        if (it_limit != req.query_params.end() && !it_limit->second.empty()) {
            try {
                limit = std::stoul(it_limit->second);
            } catch (...) {
                limit = 100;
            }
        }
        limit = std::clamp(limit, static_cast<size_t>(1), static_cast<size_t>(500));

        json result = graph_engine->extract_subgraph(account_id, depth, limit);
        if (result.contains("error")) {
            return server::HttpResponse::error(404, "Not Found", result["message"].get<std::string>());
        }

        return server::HttpResponse::json(200, result);
    });

    // Route: POST /api/v1/graph/nodes/:account_id/action (Protected: BANK_EMPLOYEE_ONLY)
    router->post("/api/v1/graph/nodes/:account_id/action", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [db](const server::HttpRequest& req, const auth::AuthContext&) {
        std::string account_id = req.path_params.at("account_id");
        auto acc_opt = db->find_account_by_id(account_id);
        if (!acc_opt.has_value()) {
            auto upi_acc = db->find_account_by_upi(account_id);
            if (upi_acc.has_value()) {
                acc_opt = upi_acc;
            } else {
                return server::HttpResponse::error(404, "Not Found", "Account node not found: " + account_id);
            }
        }

        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            return server::HttpResponse::error(400, "Bad Request", "Malformed JSON request body");
        }

        if (!body.contains("action") || !body["action"].is_string()) {
            return server::HttpResponse::error(400, "Bad Request", "Missing 'action' field in request body");
        }

        std::string action = body["action"].get<std::string>();
        models::AccountStatus new_status;
        if (action == "FREEZE") {
            new_status = models::AccountStatus::FROZEN;
        } else if (action == "FLAG") {
            new_status = models::AccountStatus::FLAGGED;
        } else if (action == "UNFREEZE" || action == "ACTIVATE") {
            new_status = models::AccountStatus::ACTIVE;
        } else {
            return server::HttpResponse::error(400, "Bad Request", "Invalid action: " + action + ". Supported actions: FREEZE, FLAG, UNFREEZE, ACTIVATE");
        }

        db->update_account_status(acc_opt->account_id, new_status);
        utils::Logger::warn("Investigator action applied to node " + acc_opt->account_id + ": Status set to " + models::account_status_to_string(new_status));

        return server::HttpResponse::json(200, {
            {"account_id", acc_opt->account_id},
            {"status", models::account_status_to_string(new_status)},
            {"message", "Node " + acc_opt->account_id + " status successfully updated to " + models::account_status_to_string(new_status)}
        });
    });

    // Route: GET /api/v1/graph/metrics (Protected: BANK_EMPLOYEE_ONLY)
    router->get("/api/v1/graph/metrics", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [graph_engine](const server::HttpRequest&, const auth::AuthContext&) {
        json metrics = graph_engine->compute_network_metrics();
        return server::HttpResponse::json(200, metrics);
    });

    // Route: GET /api/v1/evaluation/scenarios (Protected: BANK_EMPLOYEE_ONLY)
    router->get("/api/v1/evaluation/scenarios", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [db](const server::HttpRequest&, const auth::AuthContext&) {
        auto scenarios = db->list_ground_truth_scenarios();
        json arr = json::array();
        for (const auto& sc : scenarios) {
            arr.push_back(sc.to_json());
        }
        return server::HttpResponse::json(200, {
            {"total_scenarios", arr.size()},
            {"scenarios", arr}
        });
    });

    // Route: GET /api/v1/evaluation/stats (Protected: BANK_EMPLOYEE_ONLY)
    router->get("/api/v1/evaluation/stats", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [db](const server::HttpRequest&, const auth::AuthContext&) {
        auto accounts = db->list_accounts();
        auto transactions = db->list_transactions();
        auto scenarios = db->list_ground_truth_scenarios();

        size_t verified_merchants = 0;
        size_t frozen_count = 0;
        size_t flagged_count = 0;
        for (const auto& a : accounts) {
            if (a.is_verified_merchant) verified_merchants++;
            if (a.status == models::AccountStatus::FROZEN) frozen_count++;
            if (a.status == models::AccountStatus::FLAGGED) flagged_count++;
        }

        return server::HttpResponse::json(200, {
            {"total_accounts", accounts.size()},
            {"total_transactions", transactions.size()},
            {"verified_merchants", verified_merchants},
            {"flagged_nodes", flagged_count},
            {"frozen_nodes", frozen_count},
            {"ground_truth_scenarios_count", scenarios.size()}
        });
    });

    // Route: GET /api/v1/accounts (Protected: BANK_EMPLOYEE_ONLY)
    router->get("/api/v1/accounts", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [db](const server::HttpRequest& req, const auth::AuthContext&) {
        auto accounts = db->list_accounts();
        size_t limit = 50;
        size_t offset = 0;
        if (req.query_params.count("limit")) {
            try { limit = std::stoul(req.query_params.at("limit")); } catch(...) {}
        }
        if (req.query_params.count("offset")) {
            try { offset = std::stoul(req.query_params.at("offset")); } catch(...) {}
        }
        limit = std::clamp(limit, static_cast<size_t>(1), static_cast<size_t>(200));

        json arr = json::array();
        for (size_t i = offset; i < accounts.size() && arr.size() < limit; ++i) {
            arr.push_back(accounts[i].to_json());
        }

        return server::HttpResponse::json(200, {
            {"total", accounts.size()},
            {"limit", limit},
            {"offset", offset},
            {"accounts", arr}
        });
    });

    // 4. Start HTTP Server
    int port = 8080;
    auto server = std::make_unique<server::HttpServer>("0.0.0.0", port, router);
    if (!server->start()) {
        utils::Logger::error("Failed to start HTTP server.");
        return 1;
    }

    utils::Logger::info("TrustGraph Milestone 1 Core is running. Press Ctrl+C to terminate.");

    while (!g_shutdown_requested) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    utils::Logger::info("Initiating server shutdown sequence...");
    server->stop();
    utils::Logger::info("Server stopped cleanly.");
    return 0;
}
