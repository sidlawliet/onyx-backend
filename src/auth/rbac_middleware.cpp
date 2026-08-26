#include "auth/rbac_middleware.hpp"
#include <sstream>

namespace trustgraph::auth {

RbacMiddleware::RbacMiddleware(std::shared_ptr<JwtManager> jwt_manager)
    : jwt_manager_(std::move(jwt_manager)) {}

std::optional<std::string> RbacMiddleware::extract_bearer_token(const server::HttpRequest& req) {
    std::string auth_header = req.get_header("Authorization");
    if (auth_header.empty()) {
        // Also check lowercase
        auth_header = req.get_header("authorization");
    }

    if (auth_header.empty()) {
        return std::nullopt;
    }

    const std::string prefix = "Bearer ";
    if (auth_header.rfind(prefix, 0) == 0) {
        return auth_header.substr(prefix.length());
    }

    return std::nullopt;
}

std::pair<std::optional<AuthContext>, std::optional<server::HttpResponse>>
RbacMiddleware::authenticate_and_authorize(
    const server::HttpRequest& req,
    RoleRequirement requirement) const
{
    if (requirement == RoleRequirement::PUBLIC) {
        AuthContext public_ctx;
        public_ctx.is_authenticated = false;
        return {public_ctx, std::nullopt};
    }

    auto token_opt = extract_bearer_token(req);
    if (!token_opt.has_value() || token_opt->empty()) {
        return {
            std::nullopt,
            server::HttpResponse::error(401, "Unauthorized", "Missing or malformed Authorization header. Expected: Bearer <token>")
        };
    }

    auto claims_opt = jwt_manager_->verify_token(*token_opt);
    if (!claims_opt.has_value()) {
        return {
            std::nullopt,
            server::HttpResponse::error(401, "Unauthorized", "Invalid, expired, or tampered access token")
        };
    }

    auto role_enum_opt = models::string_to_user_role(claims_opt->role);
    models::UserRole user_role = role_enum_opt.value_or(models::UserRole::CONSUMER);

    // Role enforcement
    if (requirement == RoleRequirement::CONSUMER_ONLY) {
        if (user_role != models::UserRole::CONSUMER) {
            return {
                std::nullopt,
                server::HttpResponse::error(403, "Forbidden", "Access denied: Endpoint requires CONSUMER role permissions")
            };
        }
    } else if (requirement == RoleRequirement::BANK_EMPLOYEE_ONLY) {
        if (user_role != models::UserRole::BANK_EMPLOYEE) {
            return {
                std::nullopt,
                server::HttpResponse::error(403, "Forbidden", "Access denied: Endpoint requires BANK_EMPLOYEE role permissions")
            };
        }
    }

    AuthContext ctx;
    ctx.is_authenticated = true;
    ctx.user_id = claims_opt->user_id;
    ctx.username = claims_opt->username;
    ctx.role = user_role;
    ctx.associated_account_id = claims_opt->associated_account_id;

    return {ctx, std::nullopt};
}

} // namespace trustgraph::auth
