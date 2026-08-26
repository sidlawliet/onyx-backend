#include <cassert>
#include <iostream>
#include <memory>
#include "db/in_memory_store.hpp"
#include "auth/jwt_manager.hpp"
#include "auth/rbac_middleware.hpp"
#include "server/router.hpp"
#include "utils/json.hpp"

using json = nlohmann::json;
using namespace trustgraph;

void test_explainability_and_risk_verification() {
    std::cout << "[TEST] Running test_explainability_and_risk_verification..." << std::endl;

    auto db = std::make_shared<db::InMemoryStore>();
    std::string secret = "test_explainability_secret_key!";
    auto jwt_manager = std::make_shared<auth::JwtManager>(secret, 86400);
    auto rbac_middleware = std::make_shared<auth::RbacMiddleware>(jwt_manager);
    auto router = std::make_shared<server::Router>(rbac_middleware);

    // Register verify-risk route
    router->get("/api/v1/accounts/verify-risk/:upi_id", auth::RoleRequirement::ANY_AUTHENTICATED, [db](const server::HttpRequest& req, const auth::AuthContext&) {
        std::string upi_id = req.path_params.at("upi_id");
        auto acc_opt = db->find_account_by_upi(upi_id);
        if (!acc_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Recipient UPI ID not found");
        }

        const auto& acc = *acc_opt;
        std::vector<std::string> signals;
        bool is_safe = true;
        std::string risk_level = "LOW";
        std::string recommended_action = "Safe to proceed";

        if (acc.status == models::AccountStatus::FLAGGED || acc.risk_score >= 70.0) {
            signals.push_back("Recipient marked FLAGGED");
            is_safe = false;
            risk_level = "CRITICAL";
            recommended_action = "Do not send funds";
        } else {
            signals.push_back("Clean history");
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

    // Register flag-details route
    router->get("/api/v1/transactions/:transaction_id/flag-details", auth::RoleRequirement::ANY_AUTHENTICATED, [db](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
        std::string tx_id = req.path_params.at("transaction_id");
        auto tx_opt = db->find_transaction_by_id(tx_id);
        if (!tx_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Transaction not found");
        }

        if (auth_ctx.is_consumer()) {
            if (!auth_ctx.associated_account_id.has_value() ||
                (tx_opt->sender_account_id != *auth_ctx.associated_account_id &&
                 tx_opt->receiver_account_id != *auth_ctx.associated_account_id)) {
                return server::HttpResponse::error(403, "Forbidden", "Access denied");
            }
        }

        auto flag_opt = db->find_flag_by_transaction_id(tx_id);
        if (!flag_opt.has_value()) {
            return server::HttpResponse::json(200, {
                {"transaction_id", tx_opt->transaction_id},
                {"status", models::transaction_status_to_string(tx_opt->status)},
                {"risk_score", 0.0},
                {"risk_level", "LOW"}
            });
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

    // Generate tokens
    auth::JwtTokenClaims consumer_claims;
    consumer_claims.user_id = "USR-8819A";
    consumer_claims.username = "siddharth_k";
    consumer_claims.role = "CONSUMER";
    consumer_claims.associated_account_id = "ACC-7A1B8C9D";
    std::string consumer_token = jwt_manager->create_token(consumer_claims);

    auth::JwtTokenClaims other_consumer_claims;
    other_consumer_claims.user_id = "USR-OTHER";
    other_consumer_claims.username = "other_user";
    other_consumer_claims.role = "CONSUMER";
    other_consumer_claims.associated_account_id = "ACC-OTHER-99";
    std::string other_consumer_token = jwt_manager->create_token(other_consumer_claims);

    auth::JwtTokenClaims bank_claims;
    bank_claims.user_id = "USR-BANK-001";
    bank_claims.username = "analyst_raj";
    bank_claims.role = "BANK_EMPLOYEE";
    std::string bank_token = jwt_manager->create_token(bank_claims);

    // 1. Test verify-risk on suspect account
    server::HttpRequest verify_suspect_req;
    verify_suspect_req.method = server::HttpMethod::GET;
    verify_suspect_req.path = "/api/v1/accounts/verify-risk/invest_guru@ybl";
    verify_suspect_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto verify_suspect_res = router->handle_request(verify_suspect_req);
    assert(verify_suspect_res.status_code == 200);
    auto suspect_json = json::parse(verify_suspect_res.body);
    assert(suspect_json["is_safe_to_pay"] == false);
    assert(suspect_json["risk_level"] == "CRITICAL");
    assert(suspect_json["account_status"] == "FLAGGED");

    // 2. Test verify-risk on clean account
    server::HttpRequest verify_clean_req;
    verify_clean_req.method = server::HttpMethod::GET;
    verify_clean_req.path = "/api/v1/accounts/verify-risk/siddharth@okaxis";
    verify_clean_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto verify_clean_res = router->handle_request(verify_clean_req);
    assert(verify_clean_res.status_code == 200);
    auto clean_json = json::parse(verify_clean_res.body);
    assert(clean_json["is_safe_to_pay"] == true);
    assert(clean_json["risk_level"] == "LOW");

    // 3. Test verify-risk on non-existent account -> 404
    server::HttpRequest verify_404_req;
    verify_404_req.method = server::HttpMethod::GET;
    verify_404_req.path = "/api/v1/accounts/verify-risk/unknown_upi@bank";
    verify_404_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto verify_404_res = router->handle_request(verify_404_req);
    assert(verify_404_res.status_code == 404);

    // 4. Test flag-details for transaction TXN-88F19280AA (owned by consumer)
    server::HttpRequest flag_details_req;
    flag_details_req.method = server::HttpMethod::GET;
    flag_details_req.path = "/api/v1/transactions/TXN-88F19280AA/flag-details";
    flag_details_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto flag_details_res = router->handle_request(flag_details_req);
    assert(flag_details_res.status_code == 200);
    auto flag_json = json::parse(flag_details_res.body);
    assert(flag_json["transaction_id"] == "TXN-88F19280AA");
    assert(flag_json["status"] == "HELD");
    assert(flag_json["risk_score"] == 88.5);
    assert(flag_json["risk_level"] == "CRITICAL");
    assert(flag_json["explanation_title"] == "High Velocity Mule Pass-Through Detected");
    assert(flag_json["warning_reasons"].size() == 3);

    // 5. Test flag-details by unauthorized other consumer -> 403 Forbidden
    server::HttpRequest unauth_flag_req;
    unauth_flag_req.method = server::HttpMethod::GET;
    unauth_flag_req.path = "/api/v1/transactions/TXN-88F19280AA/flag-details";
    unauth_flag_req.headers["Authorization"] = "Bearer " + other_consumer_token;
    auto unauth_flag_res = router->handle_request(unauth_flag_req);
    assert(unauth_flag_res.status_code == 403);

    // 6. Test flag-details by Bank Employee -> 200 OK
    server::HttpRequest bank_flag_req;
    bank_flag_req.method = server::HttpMethod::GET;
    bank_flag_req.path = "/api/v1/transactions/TXN-88F19280AA/flag-details";
    bank_flag_req.headers["Authorization"] = "Bearer " + bank_token;
    auto bank_flag_res = router->handle_request(bank_flag_req);
    assert(bank_flag_res.status_code == 200);

    std::cout << "  -> test_explainability_and_risk_verification passed!" << std::endl;
}

int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << "   RUNNING EXPLAINABILITY API TEST SUITE  " << std::endl;
    std::cout << "==========================================" << std::endl;

    test_explainability_and_risk_verification();

    std::cout << "All Explainability API tests passed successfully!" << std::endl;
    return 0;
}
