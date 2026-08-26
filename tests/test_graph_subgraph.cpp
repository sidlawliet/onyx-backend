#include <cassert>
#include <iostream>
#include <memory>
#include "db/in_memory_store.hpp"
#include "engine/graph_engine.hpp"
#include "auth/jwt_manager.hpp"
#include "auth/rbac_middleware.hpp"
#include "server/router.hpp"
#include "utils/json.hpp"

using json = nlohmann::json;
using namespace trustgraph;

void test_graph_engine_core() {
    std::cout << "[TEST] Running test_graph_engine_core..." << std::endl;

    auto db = std::make_shared<db::InMemoryStore>();
    auto graph_engine = std::make_shared<engine::GraphEngine>(db);

    // 1. Basic Subgraph Extraction
    json sub = graph_engine->extract_subgraph("ACC-7A1B8C9D", 2, 50);
    assert(sub.contains("root_account_id"));
    assert(sub["root_account_id"] == "ACC-7A1B8C9D");
    assert(sub.contains("elements"));
    assert(sub["elements"].contains("nodes"));
    assert(sub["elements"].contains("edges"));
    assert(sub["elements"]["nodes"].size() >= 2);
    assert(sub["elements"]["edges"].size() >= 1);

    // Verify root flag
    bool found_root = false;
    for (const auto& n : sub["elements"]["nodes"]) {
        if (n["data"]["id"] == "ACC-7A1B8C9D") {
            assert(n["data"]["is_root"] == true);
            found_root = true;
        } else {
            assert(n["data"]["is_root"] == false);
        }
    }
    assert(found_root);

    // 2. Cyclic Graph Test: A -> B -> C -> A
    models::Account accA; accA.account_id = "CYC-A"; accA.upi_id = "a@upi"; accA.holder_name = "Node A"; accA.balance = 1000;
    models::Account accB; accB.account_id = "CYC-B"; accB.upi_id = "b@upi"; accB.holder_name = "Node B"; accB.balance = 1000;
    models::Account accC; accC.account_id = "CYC-C"; accC.upi_id = "c@upi"; accC.holder_name = "Node C"; accC.balance = 1000;
    db->create_account(accA);
    db->create_account(accB);
    db->create_account(accC);

    models::Transaction txAB; txAB.transaction_id = "TX-AB"; txAB.sender_account_id = "CYC-A"; txAB.receiver_account_id = "CYC-B"; txAB.amount = 100; txAB.status = models::TransactionStatus::COMPLETED;
    models::Transaction txBC; txBC.transaction_id = "TX-BC"; txBC.sender_account_id = "CYC-B"; txBC.receiver_account_id = "CYC-C"; txBC.amount = 100; txBC.status = models::TransactionStatus::COMPLETED;
    models::Transaction txCA; txCA.transaction_id = "TX-CA"; txCA.sender_account_id = "CYC-C"; txCA.receiver_account_id = "CYC-A"; txCA.amount = 100; txCA.status = models::TransactionStatus::COMPLETED;
    db->create_transaction(txAB);
    db->create_transaction(txBC);
    db->create_transaction(txCA);

    json cyc_sub = graph_engine->extract_subgraph("CYC-A", 3, 50);
    assert(cyc_sub["node_count"] == 3);
    assert(cyc_sub["edge_count"] == 3);

    // 3. Network Metrics
    json metrics = graph_engine->compute_network_metrics();
    assert(metrics.contains("total_nodes"));
    assert(metrics["total_nodes"] >= 6);
    assert(metrics.contains("total_transactions"));
    assert(metrics.contains("flagged_transactions"));
    assert(metrics.contains("total_held_volume"));

    std::cout << "  -> test_graph_engine_core passed!" << std::endl;
}

void test_graph_routes_and_rbac() {
    std::cout << "[TEST] Running test_graph_routes_and_rbac..." << std::endl;

    auto db = std::make_shared<db::InMemoryStore>();
    auto graph_engine = std::make_shared<engine::GraphEngine>(db);
    std::string secret = "test_graph_routes_secret_key!";
    auto jwt_manager = std::make_shared<auth::JwtManager>(secret, 86400);
    auto rbac_middleware = std::make_shared<auth::RbacMiddleware>(jwt_manager);
    auto router = std::make_shared<server::Router>(rbac_middleware);

    // Register Subgraph Route
    router->get("/api/v1/graph/subgraph/:account_id", auth::RoleRequirement::ANY_AUTHENTICATED, [db, graph_engine](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
        std::string account_id = req.path_params.at("account_id");
        if (auth_ctx.is_consumer()) {
            if (!auth_ctx.associated_account_id.has_value() || *auth_ctx.associated_account_id != account_id) {
                return server::HttpResponse::error(403, "Forbidden", "Access denied: Consumers can only explore their own account subgraph");
            }
        }
        json result = graph_engine->extract_subgraph(account_id, 2, 100);
        return server::HttpResponse::json(200, result);
    });

    // Register Node Action Route
    router->post("/api/v1/graph/nodes/:account_id/action", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [db](const server::HttpRequest& req, const auth::AuthContext&) {
        std::string account_id = req.path_params.at("account_id");
        json body = json::parse(req.body);
        std::string action = body.value("action", "");
        models::AccountStatus new_status = models::AccountStatus::ACTIVE;
        if (action == "FREEZE") new_status = models::AccountStatus::FROZEN;
        else if (action == "FLAG") new_status = models::AccountStatus::FLAGGED;
        else if (action == "UNFREEZE") new_status = models::AccountStatus::ACTIVE;
        db->update_account_status(account_id, new_status);
        return server::HttpResponse::json(200, {
            {"account_id", account_id},
            {"status", models::account_status_to_string(new_status)}
        });
    });

    // Tokens
    auth::JwtTokenClaims consumer_claims;
    consumer_claims.user_id = "USR-8819A";
    consumer_claims.username = "siddharth_k";
    consumer_claims.role = "CONSUMER";
    consumer_claims.associated_account_id = "ACC-7A1B8C9D";
    std::string consumer_token = jwt_manager->create_token(consumer_claims);

    auth::JwtTokenClaims bank_claims;
    bank_claims.user_id = "USR-BANK-001";
    bank_claims.username = "analyst_raj";
    bank_claims.role = "BANK_EMPLOYEE";
    std::string bank_token = jwt_manager->create_token(bank_claims);

    // 1. Consumer extracts own subgraph -> 200 OK
    server::HttpRequest own_sub_req;
    own_sub_req.method = server::HttpMethod::GET;
    own_sub_req.path = "/api/v1/graph/subgraph/ACC-7A1B8C9D";
    own_sub_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto own_sub_res = router->handle_request(own_sub_req);
    assert(own_sub_res.status_code == 200);

    // 2. Consumer extracts foreign subgraph -> 403 Forbidden
    server::HttpRequest foreign_sub_req;
    foreign_sub_req.method = server::HttpMethod::GET;
    foreign_sub_req.path = "/api/v1/graph/subgraph/ACC-9F2E4A10";
    foreign_sub_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto foreign_sub_res = router->handle_request(foreign_sub_req);
    assert(foreign_sub_res.status_code == 403);

    // 3. Bank Employee extracts foreign subgraph -> 200 OK
    server::HttpRequest bank_sub_req;
    bank_sub_req.method = server::HttpMethod::GET;
    bank_sub_req.path = "/api/v1/graph/subgraph/ACC-9F2E4A10";
    bank_sub_req.headers["Authorization"] = "Bearer " + bank_token;
    auto bank_sub_res = router->handle_request(bank_sub_req);
    assert(bank_sub_res.status_code == 200);

    // 4. Consumer attempts Node Action -> 403 Forbidden
    server::HttpRequest consumer_action_req;
    consumer_action_req.method = server::HttpMethod::POST;
    consumer_action_req.path = "/api/v1/graph/nodes/ACC-9F2E4A10/action";
    consumer_action_req.headers["Authorization"] = "Bearer " + consumer_token;
    consumer_action_req.body = "{\"action\":\"FREEZE\"}";
    auto consumer_action_res = router->handle_request(consumer_action_req);
    assert(consumer_action_res.status_code == 403);

    // 5. Bank Employee executes Node Action (FREEZE) -> 200 OK
    server::HttpRequest bank_action_req;
    bank_action_req.method = server::HttpMethod::POST;
    bank_action_req.path = "/api/v1/graph/nodes/ACC-9F2E4A10/action";
    bank_action_req.headers["Authorization"] = "Bearer " + bank_token;
    bank_action_req.body = "{\"action\":\"FREEZE\"}";
    auto bank_action_res = router->handle_request(bank_action_req);
    assert(bank_action_res.status_code == 200);
    auto action_json = json::parse(bank_action_res.body);
    assert(action_json["status"] == "FROZEN");

    auto frozen_acc = db->find_account_by_id("ACC-9F2E4A10");
    assert(frozen_acc.has_value());
    assert(frozen_acc->status == models::AccountStatus::FROZEN);

    std::cout << "  -> test_graph_routes_and_rbac passed!" << std::endl;
}

int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << "    RUNNING GRAPH SUBGRAPH TEST SUITE     " << std::endl;
    std::cout << "==========================================" << std::endl;

    test_graph_engine_core();
    test_graph_routes_and_rbac();

    std::cout << "All Graph Subgraph tests passed successfully!" << std::endl;
    return 0;
}
