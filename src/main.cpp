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
#include "controllers/account_controller.hpp"
#include "controllers/transaction_controller.hpp"
#include "controllers/complaint_controller.hpp"
#include "controllers/auth_controller.hpp"

using json = nlohmann::json;
using namespace onyx;

static std::atomic<bool> g_shutdown_requested{false};

void signal_handler(int) {
    g_shutdown_requested = true;
}

int main() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    utils::Logger::info("=================================================");
    utils::Logger::info("   ONYX Financial Fraud Engine (v1.2)     ");
    utils::Logger::info("   C++ High-Performance Backend Engine           ");
    utils::Logger::info("=================================================");

    // 1. Initialize Database & Link Dataset
    auto db = std::make_shared<db::InMemoryStore>();
    std::string db_dir = "databases";
    if (const char* env_dir = std::getenv("ONYX_DB_DIR")) {
        db_dir = env_dir;
    }
    if (db->load_from_database_dir(db_dir)) {
        utils::Logger::info("Linked ONYX Database from '" + db_dir + "': 1,000 accounts, 32,000 transactions, 5 scenarios active.");
    } else {
        utils::Logger::warn("Could not load database directory from '" + db_dir + "'; running with in-memory default fixtures.");
    }

    // Seed interactive demo portal accounts, credentials & dispute queue
    {
        std::string timestamp = "2026-08-25T14:00:00Z";

        // Rajesh Kumar (Mule Aggregator)
        auto acc_mule = db->find_account_by_id("ACC-10096");
        if (!acc_mule.has_value()) {
            models::Account a;
            a.account_id = "ACC-10096";
            a.upi_id = "rajesh.mule@oksbi";
            a.holder_name = "Rajesh Kumar";
            a.balance = 250000.00;
            a.risk_score = 94.0;
            a.status = models::AccountStatus::FLAGGED;
            a.created_at = timestamp;
            db->create_account(a);
        } else {
            acc_mule->upi_id = "rajesh.mule@oksbi";
            acc_mule->holder_name = "Rajesh Kumar";
            acc_mule->risk_score = 94.0;
            acc_mule->status = models::AccountStatus::FLAGGED;
            db->update_account(*acc_mule);
        }

        // Invest Guru
        auto acc_guru = db->find_account_by_id("ACC-9F2E4A10");
        if (!acc_guru.has_value()) {
            models::Account a;
            a.account_id = "ACC-9F2E4A10";
            a.upi_id = "invest_guru@ybl";
            a.holder_name = "Deepak Sharma (Invest Guru)";
            a.balance = 150000.00;
            a.risk_score = 88.5;
            a.status = models::AccountStatus::FLAGGED;
            a.created_at = timestamp;
            db->create_account(a);
        } else {
            acc_guru->upi_id = "invest_guru@ybl";
            acc_guru->holder_name = "Deepak Sharma (Invest Guru)";
            db->update_account(*acc_guru);
        }

        auto acc_guru_hub = db->find_account_by_id("ACC-99014");
        if (!acc_guru_hub.has_value()) {
            models::Account a;
            a.account_id = "ACC-99014";
            a.upi_id = "invest_guru_global@ybl";
            a.holder_name = "Invest Guru Global Hub";
            a.balance = 450000.00;
            a.risk_score = 89.0;
            a.status = models::AccountStatus::FLAGGED;
            a.created_at = timestamp;
            db->create_account(a);
        }

        // Vivek Singh
        auto acc_vivek = db->find_account_by_id("ACC-44910283");
        if (!acc_vivek.has_value()) {
            models::Account a;
            a.account_id = "ACC-44910283";
            a.upi_id = "vivek.phish@oksbi";
            a.holder_name = "Vivek Singh";
            a.balance = 28500.00;
            a.risk_score = 76.0;
            a.status = models::AccountStatus::FLAGGED;
            a.created_at = timestamp;
            db->create_account(a);
        }

        // Verified Merchant: Zomato
        auto acc_zomato = db->find_account_by_upi("zomato@paytm");
        if (!acc_zomato.has_value()) {
            models::Account a;
            a.account_id = "ACC-ZOMATO-01";
            a.upi_id = "zomato@paytm";
            a.holder_name = "Zomato Verified Merchant";
            a.balance = 5000000.00;
            a.risk_score = 4.0;
            a.status = models::AccountStatus::ACTIVE;
            a.is_verified_merchant = true;
            a.created_at = timestamp;
            db->create_account(a);
        }

        // Demo Bank Officers: OFFICER-901 and OFF-901
        if (!db->find_user_by_username("OFFICER-901").has_value()) {
            models::User u;
            u.user_id = "USR-OFFICER-901";
            u.username = "OFFICER-901";
            u.name = "Senior SOC Officer";
            u.password_hash = auth::PasswordHasher::hash_password("bank_secure_pass", 10000);
            u.role = models::UserRole::BANK_EMPLOYEE;
            u.associated_account_id = std::nullopt;
            u.created_at = timestamp;
            db->create_user(u);
        }
        if (!db->find_user_by_username("OFF-901").has_value()) {
            models::User u;
            u.user_id = "USR-OFF-901";
            u.username = "OFF-901";
            u.name = "Officer 901";
            u.password_hash = auth::PasswordHasher::hash_password("officer", 10000);
            u.role = models::UserRole::BANK_EMPLOYEE;
            u.associated_account_id = std::nullopt;
            u.created_at = timestamp;
            db->create_user(u);
        }

        // Demo Consumers: siddharth_kumar and siddharth_k
        if (!db->find_user_by_username("siddharth_kumar").has_value()) {
            models::User u;
            u.user_id = "USR-SIDDHARTH-KUMAR";
            u.username = "siddharth_kumar";
            u.name = "Siddharth Kumar";
            u.password_hash = auth::PasswordHasher::hash_password("secure_pass_123", 10000);
            u.role = models::UserRole::CONSUMER;
            u.associated_account_id = "ACC-7A1B8C9D";
            u.created_at = timestamp;
            db->create_user(u);
        }
        if (!db->find_user_by_username("siddharth_k").has_value()) {
            models::User u;
            u.user_id = "USR-8819A";
            u.username = "siddharth_k";
            u.name = "Siddharth Kumar";
            u.password_hash = auth::PasswordHasher::hash_password("secure_password_123", 10000);
            u.role = models::UserRole::CONSUMER;
            u.associated_account_id = "ACC-7A1B8C9D";
            u.created_at = timestamp;
            db->create_user(u);
        }

        // Seed initial triage complaints if empty
        auto existing_complaints = db->list_complaints(std::nullopt, 10);
        if (existing_complaints.empty()) {
            models::FraudComplaint c1;
            c1.complaint_id = "CMP-102";
            c1.complainant_account_id = "ACC-7A1B8C9D";
            c1.suspect_account_id = "ACC-10096";
            c1.transaction_id = "TXN-88F101";
            c1.amount = 45000.00;
            c1.scam_category = "MULE_SUSPECT";
            c1.description = "Victim reported coerced urgent funds diversion following fake telecom KYC renewal notice.";
            c1.status = "UNDER_INVESTIGATION";
            c1.created_at = "2026-08-27 14:22:10";
            db->create_complaint(c1);

            models::FraudComplaint c2;
            c2.complaint_id = "CMP-101";
            c2.complainant_account_id = "ACC-VIC-A01";
            c2.suspect_account_id = "ACC-9F2E4A10";
            c2.transaction_id = "TXN-77A001";
            c2.amount = 150000.00;
            c2.scam_category = "INVESTMENT_FRAUD";
            c2.description = "High-yield daily Telegram task investment fraud payout redirection.";
            c2.status = "FROZEN";
            c2.created_at = "2026-08-27 11:05:42";
            db->create_complaint(c2);

            models::FraudComplaint c3;
            c3.complaint_id = "CMP-100";
            c3.complainant_account_id = "ACC-VIC-B01";
            c3.suspect_account_id = "ACC-44910283";
            c3.transaction_id = "TXN-66B990";
            c3.amount = 28500.00;
            c3.scam_category = "PHISHING";
            c3.description = "Compromised credential login after phishing SMS with fake electricity bill disconnect threat.";
            c3.status = "RESOLVED";
            c3.created_at = "2026-08-26 18:40:15";
            db->create_complaint(c3);
        }
    }

    // 2. Initialize JWT Manager & RBAC Middleware
    std::string jwt_secret = "onyx_super_secret_jwt_key_2026_x99!@";
    auto jwt_manager = std::make_shared<auth::JwtManager>(jwt_secret, 86400);
    auto rbac_middleware = std::make_shared<auth::RbacMiddleware>(jwt_manager);

    // 3. Initialize Router
    auto router = std::make_shared<server::Router>(rbac_middleware);

    // Route: Health Check
    router->get("/api/v1/health", auth::RoleRequirement::PUBLIC, [](const server::HttpRequest&, const auth::AuthContext&) {
        json payload = {
            {"status", "HEALTHY"},
            {"service", "ONYX C++ Backend Engine"},
            {"version", "1.2.0"},
            {"timestamp", std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()}
        };
        return server::HttpResponse::json(200, payload);
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

    // 4. Initialize Controllers & Register Auth, Verification, Dispute & Account Routes
    auto auth_controller = std::make_shared<controllers::AuthController>(db, jwt_manager);
    auth_controller->register_routes(router);

    auto account_controller = std::make_shared<controllers::AccountController>(db);
    account_controller->register_routes(router);

    auto transaction_controller = std::make_shared<controllers::TransactionController>(db);
    transaction_controller->register_routes(router);

    auto complaint_controller = std::make_shared<controllers::ComplaintController>(db);
    complaint_controller->register_routes(router);

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
        auto it_hops = req.query_params.find("hops");
        if (it_hops != req.query_params.end() && !it_hops->second.empty()) {
            try {
                depth = std::stoi(it_hops->second);
            } catch (...) {
                depth = 2;
            }
        } else {
            auto it_depth = req.query_params.find("depth");
            if (it_depth != req.query_params.end() && !it_depth->second.empty()) {
                try {
                    depth = std::stoi(it_depth->second);
                } catch (...) {
                    depth = 2;
                }
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


    // 4. Start HTTP Server
    int port = 8080;
    if (const char* env_port = std::getenv("PORT")) {
        try {
            port = std::stoi(env_port);
        } catch (...) {
            port = 8080;
        }
    }
    auto server = std::make_unique<server::HttpServer>("0.0.0.0", port, router);
    if (!server->start()) {
        utils::Logger::error("Failed to start HTTP server.");
        return 1;
    }

    utils::Logger::info("ONYX Milestone 1 Core is running. Press Ctrl+C to terminate.");

    while (!g_shutdown_requested) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    utils::Logger::info("Initiating server shutdown sequence...");
    server->stop();
    utils::Logger::info("Server stopped cleanly.");
    return 0;
}
