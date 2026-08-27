#include <cassert>
#include <iostream>
#include <memory>
#include "db/in_memory_store.hpp"
#include "auth/jwt_manager.hpp"
#include "auth/rbac_middleware.hpp"
#include "server/router.hpp"
#include "controllers/account_controller.hpp"
#include "controllers/transaction_controller.hpp"
#include "utils/json.hpp"

using json = nlohmann::json;
using namespace onyx;

void test_explainability_and_risk_verification() {
    std::cout << "[TEST] Running test_explainability_and_risk_verification..." << std::endl;

    auto db = std::make_shared<db::InMemoryStore>();
    std::string secret = "test_explainability_secret_key!";
    auto jwt_manager = std::make_shared<auth::JwtManager>(secret, 86400);
    auto rbac_middleware = std::make_shared<auth::RbacMiddleware>(jwt_manager);
    auto router = std::make_shared<server::Router>(rbac_middleware);

    // Register controllers
    auto account_controller = std::make_shared<controllers::AccountController>(db);
    account_controller->register_routes(router);

    auto transaction_controller = std::make_shared<controllers::TransactionController>(db);
    transaction_controller->register_routes(router);

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

    // 1. Test verify-risk on suspect account by UPI ID (invest_guru@ybl)
    server::HttpRequest verify_suspect_req;
    verify_suspect_req.method = server::HttpMethod::GET;
    verify_suspect_req.path = "/api/v1/accounts/verify-risk/invest_guru@ybl";
    verify_suspect_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto verify_suspect_res = router->handle_request(verify_suspect_req);
    assert(verify_suspect_res.status_code == 200);
    auto suspect_json = json::parse(verify_suspect_res.body);
    assert(suspect_json["account_id"] == "ACC-9F2E4A10");
    assert(suspect_json["upi_id"] == "invest_guru@ybl");
    assert(suspect_json["customer_name"] == "Invest Guru Operations");
    assert(suspect_json["is_verified_merchant"] == false);
    assert(suspect_json["is_safe_to_pay"] == false);
    assert(suspect_json["risk_level"] == "CRITICAL");
    assert(suspect_json["status"] == "FLAGGED");
    assert(suspect_json["warning_reasons"].is_array());
    assert(suspect_json["complaints_count"] == 0);

    // 2. Test verify-risk on suspect account by Account ID (ACC-9F2E4A10)
    server::HttpRequest verify_acc_id_req;
    verify_acc_id_req.method = server::HttpMethod::GET;
    verify_acc_id_req.path = "/api/v1/accounts/verify-risk/ACC-9F2E4A10";
    verify_acc_id_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto verify_acc_id_res = router->handle_request(verify_acc_id_req);
    assert(verify_acc_id_res.status_code == 200);
    auto acc_id_json = json::parse(verify_acc_id_res.body);
    assert(acc_id_json["account_id"] == "ACC-9F2E4A10");
    assert(acc_id_json["upi_id"] == "invest_guru@ybl");
    assert(acc_id_json["status"] == "FLAGGED");

    // 3. Test verify-risk on benchmark Mule Aggregator (ACC-10096)
    models::Account mule_acc;
    mule_acc.account_id = "ACC-10096";
    mule_acc.upi_id = "rajesh.mule@oksbi";
    mule_acc.holder_name = "Rajesh Kumar";
    mule_acc.is_verified_merchant = false;
    mule_acc.balance = 12000.0;
    mule_acc.risk_score = 95.0;
    mule_acc.status = models::AccountStatus::FLAGGED;
    db->create_account(mule_acc);

    // Link ground truth archetype
    // Simulate 2 complaints
    models::FraudComplaint cmp1;
    cmp1.complaint_id = "CMP-MULE-1";
    cmp1.complainant_account_id = "ACC-7A1B8C9D";
    cmp1.suspect_account_id = "ACC-10096";
    cmp1.transaction_id = "TXN-SCEN-A-001";
    cmp1.amount = 15000.0;
    cmp1.scam_category = "TASK_JOB_SCAM";
    cmp1.status = "SUBMITTED";
    db->create_complaint(cmp1);

    models::FraudComplaint cmp2;
    cmp2.complaint_id = "CMP-MULE-2";
    cmp2.complainant_account_id = "ACC-OTHER-99";
    cmp2.suspect_account_id = "ACC-10096";
    cmp2.transaction_id = "TXN-SCEN-A-002";
    cmp2.amount = 15000.0;
    cmp2.scam_category = "INVESTMENT_FRAUD";
    cmp2.status = "SUBMITTED";
    db->create_complaint(cmp2);

    server::HttpRequest verify_mule_req;
    verify_mule_req.method = server::HttpMethod::GET;
    verify_mule_req.path = "/api/v1/accounts/verify-risk/ACC-10096";
    verify_mule_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto verify_mule_res = router->handle_request(verify_mule_req);
    assert(verify_mule_res.status_code == 200);
    auto mule_json = json::parse(verify_mule_res.body);

    assert(mule_json["account_id"] == "ACC-10096");
    assert(mule_json["upi_id"] == "rajesh.mule@oksbi");
    assert(mule_json["customer_name"] == "Rajesh Kumar");
    assert(mule_json["is_verified_merchant"] == false);
    assert(mule_json["risk_score"] == 95.0);
    assert(mule_json["risk_level"] == "CRITICAL");
    assert(mule_json["status"] == "FLAGGED");
    assert(mule_json["warning_reasons"].is_array());
    assert(mule_json["complaints_count"] == 2);

    // 4. Test verify-risk on clean account (siddharth@okaxis)
    server::HttpRequest verify_clean_req;
    verify_clean_req.method = server::HttpMethod::GET;
    verify_clean_req.path = "/api/v1/accounts/verify-risk/siddharth@okaxis";
    verify_clean_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto verify_clean_res = router->handle_request(verify_clean_req);
    assert(verify_clean_res.status_code == 200);
    auto clean_json = json::parse(verify_clean_res.body);
    assert(clean_json["is_safe_to_pay"] == true);
    assert(clean_json["risk_level"] == "LOW");
    assert(clean_json["status"] == "ACTIVE");

    // 5. Test verify-risk on non-existent account -> 404
    server::HttpRequest verify_404_req;
    verify_404_req.method = server::HttpMethod::GET;
    verify_404_req.path = "/api/v1/accounts/verify-risk/unknown_upi@bank";
    verify_404_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto verify_404_res = router->handle_request(verify_404_req);
    assert(verify_404_res.status_code == 404);

    // 6. Test PATCH /api/v1/accounts/:account_id/status:
    // Consumer attempt -> 403 Forbidden
    server::HttpRequest patch_consumer_req;
    patch_consumer_req.method = server::HttpMethod::PATCH;
    patch_consumer_req.path = "/api/v1/accounts/ACC-10096/status";
    patch_consumer_req.headers["Authorization"] = "Bearer " + consumer_token;
    patch_consumer_req.body = "{\"status\":\"FROZEN\"}";
    auto patch_consumer_res = router->handle_request(patch_consumer_req);
    assert(patch_consumer_res.status_code == 403);

    // Bank Employee freeze -> 200 OK
    server::HttpRequest patch_bank_req;
    patch_bank_req.method = server::HttpMethod::PATCH;
    patch_bank_req.path = "/api/v1/accounts/ACC-10096/status";
    patch_bank_req.headers["Authorization"] = "Bearer " + bank_token;
    patch_bank_req.body = "{\"status\":\"FROZEN\"}";
    auto patch_bank_res = router->handle_request(patch_bank_req);
    assert(patch_bank_res.status_code == 200);
    auto patch_json = json::parse(patch_bank_res.body);
    assert(patch_json["status"] == "FROZEN");

    // Verify status reflected in verify-risk
    auto verify_frozen_res = router->handle_request(verify_mule_req);
    assert(verify_frozen_res.status_code == 200);
    auto frozen_json = json::parse(verify_frozen_res.body);
    assert(frozen_json["status"] == "FROZEN");
    assert(frozen_json["risk_level"] == "CRITICAL");
    assert(frozen_json["is_safe_to_pay"] == false);

    // 7. Test flag-details for transaction TXN-88F19280AA (owned by consumer)
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

    // 8. Test flag-details by unauthorized other consumer -> 403 Forbidden
    server::HttpRequest unauth_flag_req;
    unauth_flag_req.method = server::HttpMethod::GET;
    unauth_flag_req.path = "/api/v1/transactions/TXN-88F19280AA/flag-details";
    unauth_flag_req.headers["Authorization"] = "Bearer " + other_consumer_token;
    auto unauth_flag_res = router->handle_request(unauth_flag_req);
    assert(unauth_flag_res.status_code == 403);

    // 9. Test flag-details by Bank Employee -> 200 OK
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
