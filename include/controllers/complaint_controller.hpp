#pragma once

#include <memory>
#include <string>
#include "server/http_types.hpp"
#include "server/router.hpp"
#include "auth/rbac_middleware.hpp"
#include "db/in_memory_store.hpp"

namespace trustgraph::controllers {

class ComplaintController {
public:
    explicit ComplaintController(std::shared_ptr<db::InMemoryStore> db);

    // Register all complaint-related routes with router
    void register_routes(std::shared_ptr<server::Router> router);

    // Endpoint: POST /api/v1/complaints (Protected: CONSUMER_ONLY)
    // Allows reporting scams even if the transaction originated externally
    server::HttpResponse file_complaint(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const;

    // Endpoint: GET /api/v1/complaints (Protected: BANK_EMPLOYEE_ONLY)
    // Triage queue for bank investigators
    server::HttpResponse list_complaints(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const;

    // Endpoint: PUT /api/v1/complaints/:complaint_id/status (Protected: BANK_EMPLOYEE_ONLY)
    // Update complaint investigation status
    server::HttpResponse update_complaint_status(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const;

private:
    std::shared_ptr<db::InMemoryStore> db_;
};

} // namespace trustgraph::controllers
