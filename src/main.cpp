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
