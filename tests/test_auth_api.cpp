#include <cassert>
#include <iostream>
#include <memory>
#include "db/in_memory_store.hpp"
#include "auth/password_hasher.hpp"
#include "auth/jwt_manager.hpp"
#include "auth/rbac_middleware.hpp"
#include "controllers/auth_controller.hpp"
#include "server/router.hpp"
#include "utils/json.hpp"

using json = nlohmann::json;
using namespace onyx;

void test_auth_login_and_rbac_pipeline() {
    std::cout << "[TEST] Running test_auth_login_and_rbac_pipeline..." << std::endl;

    auto db = std::make_shared<db::InMemoryStore>();
    std::string secret = "integration_test_secret_key_888!";
    auto jwt_manager = std::make_shared<auth::JwtManager>(secret, 86400);
    auto rbac_middleware = std::make_shared<auth::RbacMiddleware>(jwt_manager);
    auto router = std::make_shared<server::Router>(rbac_middleware);

    // Register AuthController routes (production controller)
    auto auth_controller = std::make_shared<controllers::AuthController>(db, jwt_manager);
    auth_controller->register_routes(router);

    // Register /api/v1/admin/audit-summary (BANK_EMPLOYEE_ONLY)
    router->get("/api/v1/admin/audit-summary", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [](const server::HttpRequest&, const auth::AuthContext& ctx) {
        return server::HttpResponse::json(200, {{"status", "SECURE_AUDIT_LOG_ACCESSED"}, {"viewer", ctx.username}});
    });

    // =========================================================================
    // 1. Consumer Registration: Name, Account Number, Password
    // =========================================================================
    server::HttpRequest reg_consumer_req;
    reg_consumer_req.method = server::HttpMethod::POST;
    reg_consumer_req.path = "/api/v1/auth/register";
    reg_consumer_req.body = json({
        {"name", "Rahul Sharma"},
        {"account_number", "ACC-449120"},
        {"password", "RahulPass@2026"}
    }).dump();

    auto reg_consumer_res = router->handle_request(reg_consumer_req);
    assert(reg_consumer_res.status_code == 201);
    auto reg_consumer_json = json::parse(reg_consumer_res.body);
    assert(reg_consumer_json.contains("access_token"));
    assert(reg_consumer_json["user"]["name"] == "Rahul Sharma");
    assert(reg_consumer_json["user"]["role"] == "CONSUMER");
    assert(reg_consumer_json["user"]["associated_account_id"] == "ACC-449120");
    assert(reg_consumer_json["account"]["account_id"] == "ACC-449120");
    assert(reg_consumer_json["account"]["holder_name"] == "Rahul Sharma");

    // =========================================================================
    // 2. Consumer Login: Name, Account Number, Password
    // =========================================================================
    server::HttpRequest login_consumer_req;
    login_consumer_req.method = server::HttpMethod::POST;
    login_consumer_req.path = "/api/v1/auth/login";
    login_consumer_req.body = json({
        {"name", "Rahul Sharma"},
        {"account_number", "ACC-449120"},
        {"password", "RahulPass@2026"}
    }).dump();

    auto login_consumer_res = router->handle_request(login_consumer_req);
    assert(login_consumer_res.status_code == 200);
    auto login_consumer_json = json::parse(login_consumer_res.body);
    assert(login_consumer_json.contains("access_token"));
    std::string rahul_token = login_consumer_json["access_token"].get<std::string>();
    assert(login_consumer_json["user"]["role"] == "CONSUMER");
    assert(login_consumer_json["user"]["associated_account_id"] == "ACC-449120");

    // =========================================================================
    // 3. Consumer Login for Existing Seeded User: Siddharth Kumar (ACC-7A1B8C9D)
    // =========================================================================
    server::HttpRequest login_seeded_consumer_req;
    login_seeded_consumer_req.method = server::HttpMethod::POST;
    login_seeded_consumer_req.path = "/api/v1/auth/login";
    login_seeded_consumer_req.body = json({
        {"name", "Siddharth Kumar"},
        {"account_number", "ACC-7A1B8C9D"},
        {"password", "secure_password_123"}
    }).dump();

    auto login_seeded_consumer_res = router->handle_request(login_seeded_consumer_req);
    assert(login_seeded_consumer_res.status_code == 200);
    auto login_seeded_json = json::parse(login_seeded_consumer_res.body);
    std::string consumer_token = login_seeded_json["access_token"].get<std::string>();
    assert(login_seeded_json["user"]["associated_account_id"] == "ACC-7A1B8C9D");

    // =========================================================================
    // 4. Bank Employee Registration: Username & Password
    // =========================================================================
    server::HttpRequest reg_bank_req;
    reg_bank_req.method = server::HttpMethod::POST;
    reg_bank_req.path = "/api/v1/auth/register";
    reg_bank_req.body = json({
        {"username", "investigator_vikram"},
        {"password", "VikramPass#2026"},
        {"role", "BANK_EMPLOYEE"}
    }).dump();

    auto reg_bank_res = router->handle_request(reg_bank_req);
    assert(reg_bank_res.status_code == 201);
    auto reg_bank_json = json::parse(reg_bank_res.body);
    assert(reg_bank_json.contains("access_token"));
    assert(reg_bank_json["user"]["username"] == "investigator_vikram");
    assert(reg_bank_json["user"]["role"] == "BANK_EMPLOYEE");
    assert(reg_bank_json["user"]["associated_account_id"].is_null());

    // =========================================================================
    // 5. Bank Employee Login: Username & Password (no account number)
    // =========================================================================
    server::HttpRequest login_bank_req;
    login_bank_req.method = server::HttpMethod::POST;
    login_bank_req.path = "/api/v1/auth/login";
    login_bank_req.body = json({
        {"username", "investigator_vikram"},
        {"password", "VikramPass#2026"}
    }).dump();

    auto login_bank_res = router->handle_request(login_bank_req);
    assert(login_bank_res.status_code == 200);
    auto login_bank_json = json::parse(login_bank_res.body);
    std::string vikram_token = login_bank_json["access_token"].get<std::string>();
    assert(login_bank_json["user"]["role"] == "BANK_EMPLOYEE");

    // =========================================================================
    // 6. Seeded Bank Employee Login: analyst_raj
    // =========================================================================
    server::HttpRequest seeded_bank_req;
    seeded_bank_req.method = server::HttpMethod::POST;
    seeded_bank_req.path = "/api/v1/auth/login";
    seeded_bank_req.body = json({
        {"username", "analyst_raj"},
        {"password", "bank_employee_pass_456"}
    }).dump();

    auto seeded_bank_res = router->handle_request(seeded_bank_req);
    assert(seeded_bank_res.status_code == 200);
    auto seeded_bank_json = json::parse(seeded_bank_res.body);
    std::string bank_token = seeded_bank_json["access_token"].get<std::string>();
    assert(seeded_bank_json["user"]["role"] == "BANK_EMPLOYEE");

    // =========================================================================
    // 7. Legacy Consumer Login: username + password + role
    // =========================================================================
    server::HttpRequest legacy_req;
    legacy_req.method = server::HttpMethod::POST;
    legacy_req.path = "/api/v1/auth/login";
    legacy_req.body = json({
        {"username", "siddharth_k"},
        {"password", "secure_password_123"},
        {"role", "CONSUMER"}
    }).dump();

    auto legacy_res = router->handle_request(legacy_req);
    assert(legacy_res.status_code == 200);

    // =========================================================================
    // 8. Error Validations
    // =========================================================================
    // 8a. Consumer registration duplicate account number -> 409 Conflict
    server::HttpRequest dup_acc_req;
    dup_acc_req.method = server::HttpMethod::POST;
    dup_acc_req.path = "/api/v1/auth/register";
    dup_acc_req.body = json({
        {"name", "Rahul Sharma 2"},
        {"account_number", "ACC-449120"},
        {"password", "AnotherPass123"}
    }).dump();
    auto dup_acc_res = router->handle_request(dup_acc_req);
    assert(dup_acc_res.status_code == 409);

    // 8b. Consumer registration missing name -> 400 Bad Request
    server::HttpRequest missing_name_req;
    missing_name_req.method = server::HttpMethod::POST;
    missing_name_req.path = "/api/v1/auth/register";
    missing_name_req.body = json({
        {"account_number", "ACC-999000"},
        {"password", "Pass123"}
    }).dump();
    auto missing_name_res = router->handle_request(missing_name_req);
    assert(missing_name_res.status_code == 400);

    // 8c. Consumer login with mismatched name -> 401 Unauthorized
    server::HttpRequest mismatch_name_req;
    mismatch_name_req.method = server::HttpMethod::POST;
    mismatch_name_req.path = "/api/v1/auth/login";
    mismatch_name_req.body = json({
        {"name", "Wrong Name"},
        {"account_number", "ACC-449120"},
        {"password", "RahulPass@2026"}
    }).dump();
    auto mismatch_name_res = router->handle_request(mismatch_name_req);
    assert(mismatch_name_res.status_code == 401);

    // 8d. Incorrect password -> 401 Unauthorized
    server::HttpRequest bad_pass_req;
    bad_pass_req.method = server::HttpMethod::POST;
    bad_pass_req.path = "/api/v1/auth/login";
    bad_pass_req.body = json({
        {"name", "Rahul Sharma"},
        {"account_number", "ACC-449120"},
        {"password", "wrong_password"}
    }).dump();
    auto bad_pass_res = router->handle_request(bad_pass_req);
    assert(bad_pass_res.status_code == 401);

    // 8e. Bank employee duplicate username -> 409 Conflict
    server::HttpRequest dup_emp_req;
    dup_emp_req.method = server::HttpMethod::POST;
    dup_emp_req.path = "/api/v1/auth/register";
    dup_emp_req.body = json({
        {"username", "investigator_vikram"},
        {"password", "NewPass#2026"},
        {"role", "BANK_EMPLOYEE"}
    }).dump();
    auto dup_emp_res = router->handle_request(dup_emp_req);
    assert(dup_emp_res.status_code == 409);

    // =========================================================================
    // 9. RBAC & Route Access Validations
    // =========================================================================
    // 9a. Accessing Protected Route without Token -> 401 Unauthorized
    server::HttpRequest unauth_req;
    unauth_req.method = server::HttpMethod::GET;
    unauth_req.path = "/api/v1/auth/me";
    auto unauth_res = router->handle_request(unauth_req);
    assert(unauth_res.status_code == 401);

    // 9b. Accessing Protected Route with Valid Consumer Token -> 200 OK
    server::HttpRequest auth_req;
    auth_req.method = server::HttpMethod::GET;
    auth_req.path = "/api/v1/auth/me";
    auth_req.headers["Authorization"] = "Bearer " + rahul_token;
    auto auth_res = router->handle_request(auth_req);
    assert(auth_res.status_code == 200);
    auto auth_json = json::parse(auth_res.body);
    assert(auth_json["name"] == "Rahul Sharma");

    // 9c. Consumer accessing Consumer-Only Route (/api/v1/consumer/my-account) -> 200 OK
    server::HttpRequest consumer_route_req;
    consumer_route_req.method = server::HttpMethod::GET;
    consumer_route_req.path = "/api/v1/consumer/my-account";
    consumer_route_req.headers["Authorization"] = "Bearer " + rahul_token;
    auto consumer_route_res = router->handle_request(consumer_route_req);
    assert(consumer_route_res.status_code == 200);
    auto acc_json = json::parse(consumer_route_res.body);
    assert(acc_json["account_id"] == "ACC-449120");

    // 9d. Bank Employee accessing Consumer-Only Route -> 403 Forbidden
    server::HttpRequest bank_on_consumer_req;
    bank_on_consumer_req.method = server::HttpMethod::GET;
    bank_on_consumer_req.path = "/api/v1/consumer/my-account";
    bank_on_consumer_req.headers["Authorization"] = "Bearer " + vikram_token;
    auto bank_on_consumer_res = router->handle_request(bank_on_consumer_req);
    assert(bank_on_consumer_res.status_code == 403);

    // 9e. Bank Employee accessing Bank-Only Route (/api/v1/admin/audit-summary) -> 200 OK
    server::HttpRequest bank_route_req;
    bank_route_req.method = server::HttpMethod::GET;
    bank_route_req.path = "/api/v1/admin/audit-summary";
    bank_route_req.headers["Authorization"] = "Bearer " + bank_token;
    auto bank_route_res = router->handle_request(bank_route_req);
    assert(bank_route_res.status_code == 200);

    // 9f. Consumer accessing Bank-Only Route -> 403 Forbidden
    server::HttpRequest consumer_on_bank_req;
    consumer_on_bank_req.method = server::HttpMethod::GET;
    consumer_on_bank_req.path = "/api/v1/admin/audit-summary";
    consumer_on_bank_req.headers["Authorization"] = "Bearer " + rahul_token;
    auto consumer_on_bank_res = router->handle_request(consumer_on_bank_req);
    assert(consumer_on_bank_res.status_code == 403);

    std::cout << "  -> test_auth_login_and_rbac_pipeline passed successfully!" << std::endl;
}

int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << "   RUNNING AUTH API & RBAC TEST SUITE     " << std::endl;
    std::cout << "==========================================" << std::endl;

    test_auth_login_and_rbac_pipeline();

    std::cout << "All Auth API & RBAC tests passed successfully!" << std::endl;
    return 0;
}
