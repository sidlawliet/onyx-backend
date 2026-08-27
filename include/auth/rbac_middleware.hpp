#pragma once

#include <string>
#include <optional>
#include <memory>
#include "models/user.hpp"
#include "auth/jwt_manager.hpp"
#include "server/http_types.hpp"

namespace onyx::auth {

enum class RoleRequirement {
    PUBLIC,
    ANY_AUTHENTICATED,
    CONSUMER_ONLY,
    BANK_EMPLOYEE_ONLY,
    CONSUMER_OR_BANK
};

struct AuthContext {
    bool is_authenticated = false;
    std::string user_id;
    std::string username;
    models::UserRole role = models::UserRole::CONSUMER;
    std::optional<std::string> associated_account_id;

    bool is_consumer() const {
        return is_authenticated && role == models::UserRole::CONSUMER;
    }

    bool is_bank_employee() const {
        return is_authenticated && role == models::UserRole::BANK_EMPLOYEE;
    }
};

class RbacMiddleware {
public:
    explicit RbacMiddleware(std::shared_ptr<JwtManager> jwt_manager);

    // Extracts and validates Bearer token from Request headers
    std::pair<std::optional<AuthContext>, std::optional<server::HttpResponse>> authenticate_and_authorize(
        const server::HttpRequest& req,
        RoleRequirement requirement) const;

    // Helper to extract Bearer token string from Authorization header
    static std::optional<std::string> extract_bearer_token(const server::HttpRequest& req);

private:
    std::shared_ptr<JwtManager> jwt_manager_;
};

} // namespace onyx::auth
