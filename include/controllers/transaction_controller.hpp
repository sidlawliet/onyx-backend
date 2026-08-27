#pragma once

#include <memory>
#include <string>
#include "server/http_types.hpp"
#include "server/router.hpp"
#include "auth/rbac_middleware.hpp"
#include "db/in_memory_store.hpp"

namespace onyx::controllers {

class TransactionController {
public:
    explicit TransactionController(std::shared_ptr<db::InMemoryStore> db);

    // Register all transaction-related routes with router
    void register_routes(std::shared_ptr<server::Router> router);

    // Endpoint: GET /api/v1/transactions/:transaction_id/flag-details
    // Explainable fraud flag auditing
    server::HttpResponse get_flag_details(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const;

    // Endpoint: GET /api/v1/transactions
    // Historical transaction ledger
    server::HttpResponse list_transactions(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const;

    // Endpoint: GET /api/v1/transactions/:transaction_id
    // Single transaction inspection
    server::HttpResponse get_transaction(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const;

    // Endpoint: POST /api/v1/transactions
    // Decoupled legacy transfer simulation (preserves backend sandbox capability)
    server::HttpResponse execute_transaction(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const;

private:
    std::shared_ptr<db::InMemoryStore> db_;
};

} // namespace onyx::controllers
