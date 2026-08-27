#pragma once

#include <memory>
#include <string>
#include "db/database_interface.hpp"
#include "auth/jwt_manager.hpp"
#include "server/router.hpp"
#include "server/http_types.hpp"

namespace trustgraph::controllers {

class AuthController {
public:
    AuthController(std::shared_ptr<db::IDatabase> db, std::shared_ptr<auth::JwtManager> jwt_manager);

    void register_routes(std::shared_ptr<server::Router> router);

    server::HttpResponse login(const server::HttpRequest& req, const auth::AuthContext& ctx);
    server::HttpResponse register_account(const server::HttpRequest& req, const auth::AuthContext& ctx);
    server::HttpResponse get_me(const server::HttpRequest& req, const auth::AuthContext& ctx);
    server::HttpResponse get_my_account(const server::HttpRequest& req, const auth::AuthContext& ctx);

private:
    std::shared_ptr<db::IDatabase> db_;
    std::shared_ptr<auth::JwtManager> jwt_manager_;
};

} // namespace trustgraph::controllers
