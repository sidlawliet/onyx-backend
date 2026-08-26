#include <cassert>
#include <iostream>
#include <memory>
#include "db/in_memory_store.hpp"
#include "auth/password_hasher.hpp"
#include "auth/jwt_manager.hpp"
#include "auth/rbac_middleware.hpp"
#include "server/router.hpp"
#include "utils/json.hpp"

using json = nlohmann::json;
using namespace trustgraph;

void test_auth_login_and_rbac_pipeline() {
    std::cout << "[TEST] Running test_auth_login_and_rbac_pipeline..." << std::endl;

    auto db = std::make_shared<db::InMemoryStore>();
    std::string secret = "integration_test_secret_key_888!";
    auto jwt_manager = std::make_shared<auth::JwtManager>(secret, 86400);
    auto rbac_middleware = std::make_shared<auth::RbacMiddleware>(jwt_manager);
    auto router = std::make_shared<server::Router>(rbac_middleware);

    // Register login route
    router->post("/api/v1/auth/login", auth::RoleRequirement::PUBLIC, [db, jwt_manager](const server::HttpRequest& req, const auth::AuthContext&) {
        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            return server::HttpResponse::error(400, "Bad Request", "Malformed JSON");
        }

        std::string username = body.value("username", "");
        std::string password = body.value("password", "");
        std::string role_str = body.value("role", "");

        auto role_opt = models::string_to_user_role(role_str);
        if (!role_opt.has_value()) {
            return server::HttpResponse::error(400, "Bad Request", "Invalid role");
        }

        auto user_opt = db->find_user_by_username(username);
        if (!user_opt.has_value() || user_opt->role != *role_opt) {
            return server::HttpResponse::error(401, "Unauthorized", "Invalid credentials");
        }

        if (!auth::PasswordHasher::verify_password(password, user_opt->password_hash)) {
            return server::HttpResponse::error(401, "Unauthorized", "Invalid credentials");
        }

        auth::JwtTokenClaims claims;
        claims.user_id = user_opt->user_id;
        claims.username = user_opt->username;
        claims.role = models::user_role_to_string(user_opt->role);
        claims.associated_account_id = user_opt->associated_account_id;

        std::string token = jwt_manager->create_token(claims);

        json response = {
            {"access_token", token},
            {"token_type", "Bearer"},
            {"expires_in", 86400},
            {"user", user_opt->to_json_public()}
        };
        return server::HttpResponse::json(200, response);
    });

    // Register /api/v1/auth/me (ANY_AUTHENTICATED)
    router->get("/api/v1/auth/me", auth::RoleRequirement::ANY_AUTHENTICATED, [db](const server::HttpRequest&, const auth::AuthContext& ctx) {
        auto user = db->find_user_by_id(ctx.user_id);
        return server::HttpResponse::json(200, user->to_json_public());
    });

    // Register /api/v1/consumer/my-account (CONSUMER_ONLY)
    router->get("/api/v1/consumer/my-account", auth::RoleRequirement::CONSUMER_ONLY, [db](const server::HttpRequest&, const auth::AuthContext& ctx) {
        auto acc = db->find_account_by_id(*ctx.associated_account_id);
        return server::HttpResponse::json(200, acc->to_json());
    });

    // Register /api/v1/admin/audit-summary (BANK_EMPLOYEE_ONLY)
    router->get("/api/v1/admin/audit-summary", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [](const server::HttpRequest&, const auth::AuthContext& ctx) {
        return server::HttpResponse::json(200, {{"status", "SECURE_AUDIT_LOG_ACCESSED"}, {"viewer", ctx.username}});
    });

    // 1. Test Successful Consumer Login
    server::HttpRequest login_req;
    login_req.method = server::HttpMethod::POST;
    login_req.path = "/api/v1/auth/login";
    login_req.body = "{\"username\":\"siddharth_k\",\"password\":\"secure_password_123\",\"role\":\"CONSUMER\"}";

    auto login_res = router->handle_request(login_req);
    assert(login_res.status_code == 200);
    auto login_json = json::parse(login_res.body);
    assert(login_json.contains("access_token"));
    std::string consumer_token = login_json["access_token"].get<std::string>();
    assert(login_json["user"]["role"] == "CONSUMER");
    assert(login_json["user"]["associated_account_id"] == "ACC-7A1B8C9D");

    // 2. Test Successful Bank Employee Login
    server::HttpRequest bank_login_req;
    bank_login_req.method = server::HttpMethod::POST;
    bank_login_req.path = "/api/v1/auth/login";
    bank_login_req.body = "{\"username\":\"analyst_raj\",\"password\":\"bank_employee_pass_456\",\"role\":\"BANK_EMPLOYEE\"}";

    auto bank_login_res = router->handle_request(bank_login_req);
    assert(bank_login_res.status_code == 200);
    auto bank_login_json = json::parse(bank_login_res.body);
    std::string bank_token = bank_login_json["access_token"].get<std::string>();
    assert(bank_login_json["user"]["role"] == "BANK_EMPLOYEE");

    // 3. Test Invalid Password
    server::HttpRequest bad_pass_req;
    bad_pass_req.method = server::HttpMethod::POST;
    bad_pass_req.path = "/api/v1/auth/login";
    bad_pass_req.body = "{\"username\":\"siddharth_k\",\"password\":\"wrong_pass\",\"role\":\"CONSUMER\"}";
    auto bad_pass_res = router->handle_request(bad_pass_req);
    assert(bad_pass_res.status_code == 401);

    // 4. Test Role Mismatch (trying to login as BANK_EMPLOYEE with consumer user)
    server::HttpRequest mismatch_req;
    mismatch_req.method = server::HttpMethod::POST;
    mismatch_req.path = "/api/v1/auth/login";
    mismatch_req.body = "{\"username\":\"siddharth_k\",\"password\":\"secure_password_123\",\"role\":\"BANK_EMPLOYEE\"}";
    auto mismatch_res = router->handle_request(mismatch_req);
    assert(mismatch_res.status_code == 401);

    // 5. Test Accessing Protected Route without Token
    server::HttpRequest unauth_req;
    unauth_req.method = server::HttpMethod::GET;
    unauth_req.path = "/api/v1/auth/me";
    auto unauth_res = router->handle_request(unauth_req);
    assert(unauth_res.status_code == 401);

    // 6. Test Accessing Protected Route with Valid Consumer Token
    server::HttpRequest auth_req;
    auth_req.method = server::HttpMethod::GET;
    auth_req.path = "/api/v1/auth/me";
    auth_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto auth_res = router->handle_request(auth_req);
    assert(auth_res.status_code == 200);
    auto auth_json = json::parse(auth_res.body);
    assert(auth_json["username"] == "siddharth_k");

    // 7. Test Consumer accessing Consumer-Only Route
    server::HttpRequest consumer_route_req;
    consumer_route_req.method = server::HttpMethod::GET;
    consumer_route_req.path = "/api/v1/consumer/my-account";
    consumer_route_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto consumer_route_res = router->handle_request(consumer_route_req);
    assert(consumer_route_res.status_code == 200);
    auto acc_json = json::parse(consumer_route_res.body);
    assert(acc_json["account_id"] == "ACC-7A1B8C9D");

    // 8. Test Bank Employee accessing Consumer-Only Route -> 403 Forbidden
    server::HttpRequest bank_on_consumer_req;
    bank_on_consumer_req.method = server::HttpMethod::GET;
    bank_on_consumer_req.path = "/api/v1/consumer/my-account";
    bank_on_consumer_req.headers["Authorization"] = "Bearer " + bank_token;
    auto bank_on_consumer_res = router->handle_request(bank_on_consumer_req);
    assert(bank_on_consumer_res.status_code == 403);

    // 9. Test Bank Employee accessing Bank-Only Route -> 200 OK
    server::HttpRequest bank_route_req;
    bank_route_req.method = server::HttpMethod::GET;
    bank_route_req.path = "/api/v1/admin/audit-summary";
    bank_route_req.headers["Authorization"] = "Bearer " + bank_token;
    auto bank_route_res = router->handle_request(bank_route_req);
    assert(bank_route_res.status_code == 200);

    // 10. Test Consumer accessing Bank-Only Route -> 403 Forbidden
    server::HttpRequest consumer_on_bank_req;
    consumer_on_bank_req.method = server::HttpMethod::GET;
    consumer_on_bank_req.path = "/api/v1/admin/audit-summary";
    consumer_on_bank_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto consumer_on_bank_res = router->handle_request(consumer_on_bank_req);
    assert(consumer_on_bank_res.status_code == 403);

    std::cout << "  -> test_auth_login_and_rbac_pipeline passed!" << std::endl;
}

int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << "   RUNNING AUTH API & RBAC TEST SUITE     " << std::endl;
    std::cout << "==========================================" << std::endl;

    test_auth_login_and_rbac_pipeline();

    std::cout << "All Auth API & RBAC tests passed successfully!" << std::endl;
    return 0;
}
