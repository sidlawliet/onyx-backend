#pragma once

#include <memory>
#include <string>
#include <vector>
#include "server/http_types.hpp"
#include "server/router.hpp"
#include "auth/rbac_middleware.hpp"
#include "db/in_memory_store.hpp"

namespace onyx::controllers {

class AccountController {
public:
    explicit AccountController(std::shared_ptr<db::InMemoryStore> db);

    // Register all account-related routes with router
    void register_routes(std::shared_ptr<server::Router> router);

    // Endpoint: GET /api/v1/accounts/verify-risk/:identifier
    // Seamlessly accepts either a UPI ID or an Account Number
    server::HttpResponse verify_risk(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const;

    // Endpoint: PATCH /api/v1/accounts/:account_id/status
    // Allows bank employees to toggle account states (ACTIVE, FLAGGED, FROZEN)
    server::HttpResponse update_status(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const;

    // Endpoint: GET /api/v1/accounts
    // Paginated account listing for bank investigations
    server::HttpResponse list_accounts(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const;

private:
    std::shared_ptr<db::InMemoryStore> db_;
    std::vector<std::string> generate_warning_reasons(const models::Account& acc, size_t complaints_count) const;
};

} // namespace onyx::controllers
