#include "controllers/auth_controller.hpp"
#include "auth/password_hasher.hpp"
#include "utils/logger.hpp"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cctype>

namespace trustgraph::controllers {

namespace {

std::string to_lower_str(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

std::string get_current_iso_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
#if defined(_WIN32) || defined(_WIN64)
    gmtime_s(&tm_buf, &tt);
#else
    gmtime_r(&tt, &tm_buf);
#endif
    std::stringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

} // anonymous namespace

AuthController::AuthController(std::shared_ptr<db::IDatabase> db, std::shared_ptr<auth::JwtManager> jwt_manager)
    : db_(std::move(db)), jwt_manager_(std::move(jwt_manager)) {}

void AuthController::register_routes(std::shared_ptr<server::Router> router) {
    // 1. Login endpoint (PUBLIC)
    router->post("/api/v1/auth/login", auth::RoleRequirement::PUBLIC, [this](const server::HttpRequest& req, const auth::AuthContext& ctx) {
        return this->login(req, ctx);
    });

    // 2. Account creation / registration endpoints (PUBLIC)
    router->post("/api/v1/auth/register", auth::RoleRequirement::PUBLIC, [this](const server::HttpRequest& req, const auth::AuthContext& ctx) {
        return this->register_account(req, ctx);
    });
    router->post("/api/v1/auth/signup", auth::RoleRequirement::PUBLIC, [this](const server::HttpRequest& req, const auth::AuthContext& ctx) {
        return this->register_account(req, ctx);
    });
    router->post("/api/v1/auth/create-account", auth::RoleRequirement::PUBLIC, [this](const server::HttpRequest& req, const auth::AuthContext& ctx) {
        return this->register_account(req, ctx);
    });

    // 3. User profile verification (ANY_AUTHENTICATED)
    router->get("/api/v1/auth/me", auth::RoleRequirement::ANY_AUTHENTICATED, [this](const server::HttpRequest& req, const auth::AuthContext& ctx) {
        return this->get_me(req, ctx);
    });

    // 4. Consumer account detail (CONSUMER_ONLY)
    router->get("/api/v1/consumer/my-account", auth::RoleRequirement::CONSUMER_ONLY, [this](const server::HttpRequest& req, const auth::AuthContext& ctx) {
        return this->get_my_account(req, ctx);
    });
}

server::HttpResponse AuthController::register_account(const server::HttpRequest& req, const auth::AuthContext&) {
    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (...) {
        return server::HttpResponse::error(400, "Bad Request", "Malformed JSON request body");
    }

    std::string name;
    if (body.contains("name") && body["name"].is_string()) name = body["name"].get<std::string>();
    else if (body.contains("holder_name") && body["holder_name"].is_string()) name = body["holder_name"].get<std::string>();
    else if (body.contains("customer_name") && body["customer_name"].is_string()) name = body["customer_name"].get<std::string>();

    std::string account_number;
    if (body.contains("account_number") && body["account_number"].is_string()) account_number = body["account_number"].get<std::string>();
    else if (body.contains("account_id") && body["account_id"].is_string()) account_number = body["account_id"].get<std::string>();

    std::string username;
    if (body.contains("username") && body["username"].is_string()) username = body["username"].get<std::string>();

    std::string password;
    if (body.contains("password") && body["password"].is_string()) password = body["password"].get<std::string>();

    std::string role_str = "CONSUMER";
    if (body.contains("role") && body["role"].is_string()) role_str = body["role"].get<std::string>();

    std::string upi_id;
    if (body.contains("upi_id") && body["upi_id"].is_string()) upi_id = body["upi_id"].get<std::string>();

    double initial_balance = 50000.00;
    if (body.contains("initial_balance") && body["initial_balance"].is_number()) {
        initial_balance = body["initial_balance"].get<double>();
    }

    std::string timestamp = get_current_iso_timestamp();

    // Persona 1: Bank Employee Registration (uses username and password, with role == BANK_EMPLOYEE)
    if (role_str == "BANK_EMPLOYEE" || (account_number.empty() && !username.empty() && role_str != "CONSUMER")) {
        if (username.empty()) {
            if (!name.empty()) username = name;
            else return server::HttpResponse::error(400, "Bad Request", "Missing required fields: username, password");
        }
        if (password.empty()) {
            return server::HttpResponse::error(400, "Bad Request", "Missing required password");
        }

        if (db_->find_user_by_username(username).has_value()) {
            return server::HttpResponse::error(409, "Conflict", "Employee username already registered");
        }

        models::User emp_user;
        emp_user.user_id = "USR-EMP-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count() % 100000);
        emp_user.username = username;
        emp_user.name = name.empty() ? username : name;
        emp_user.password_hash = auth::PasswordHasher::hash_password(password);
        emp_user.role = models::UserRole::BANK_EMPLOYEE;
        emp_user.associated_account_id = std::nullopt;
        emp_user.created_at = timestamp;

        db_->create_user(emp_user);

        auth::JwtTokenClaims claims;
        claims.user_id = emp_user.user_id;
        claims.username = emp_user.username;
        claims.role = "BANK_EMPLOYEE";
        claims.associated_account_id = std::nullopt;
        std::string token = jwt_manager_->create_token(claims);

        utils::Logger::info("Bank employee registered: " + username);

        return server::HttpResponse::json(201, {
            {"message", "Bank employee profile registered successfully"},
            {"access_token", token},
            {"token_type", "Bearer"},
            {"expires_in", jwt_manager_->get_default_expiry_seconds()},
            {"user", emp_user.to_json_public()}
        });
    }

    // Persona 2: Consumer Registration (adds name, account_number, and password)
    if (name.empty() || account_number.empty() || password.empty()) {
        return server::HttpResponse::error(400, "Bad Request", "Missing required fields: name, account_number, password");
    }

    // Check if user already exists for this account number
    auto existing_user = db_->find_user_by_account_id(account_number);
    if (!existing_user.has_value()) {
        existing_user = db_->find_user_by_username(account_number);
    }
    if (existing_user.has_value()) {
        return server::HttpResponse::error(409, "Conflict", "A user profile already exists for this account number");
    }

    // Check if account exists in ledger; if not, provision a new one
    auto existing_acc = db_->find_account_by_id(account_number);
    models::Account acc;
    if (existing_acc.has_value()) {
        acc = *existing_acc;
    } else {
        acc.account_id = account_number;
        acc.holder_name = name;
        if (!upi_id.empty()) {
            acc.upi_id = upi_id;
        } else {
            std::string clean_name;
            for (char c : name) {
                if (std::isalnum(static_cast<unsigned char>(c))) clean_name += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                else if (c == ' ') clean_name += '.';
            }
            if (clean_name.empty()) clean_name = "user." + account_number;
            std::string cand_upi = clean_name + "@oksbi";
            if (db_->find_account_by_upi(cand_upi).has_value()) {
                cand_upi = clean_name + "." + account_number + "@oksbi";
            }
            acc.upi_id = cand_upi;
        }
        acc.balance = (initial_balance > 0.0) ? initial_balance : 50000.00;
        acc.risk_score = 0.0;
        acc.status = models::AccountStatus::ACTIVE;
        acc.created_at = timestamp;
        db_->create_account(acc);
    }

    // Provision Consumer User
    models::User consumer_user;
    consumer_user.user_id = "USR-" + account_number;
    consumer_user.username = username.empty() ? account_number : username;
    consumer_user.name = name;
    consumer_user.password_hash = auth::PasswordHasher::hash_password(password);
    consumer_user.role = models::UserRole::CONSUMER;
    consumer_user.associated_account_id = account_number;
    consumer_user.created_at = timestamp;

    if (!db_->create_user(consumer_user)) {
        // If username had collision, fallback to unique account-based username
        consumer_user.username = account_number;
        db_->create_user(consumer_user);
    }

    // Generate JWT access token
    auth::JwtTokenClaims claims;
    claims.user_id = consumer_user.user_id;
    claims.username = consumer_user.username;
    claims.role = "CONSUMER";
    claims.associated_account_id = account_number;
    std::string token = jwt_manager_->create_token(claims);

    utils::Logger::info("Consumer account registered: " + name + " (" + account_number + ")");

    return server::HttpResponse::json(201, {
        {"message", "Consumer account created successfully"},
        {"access_token", token},
        {"token_type", "Bearer"},
        {"expires_in", jwt_manager_->get_default_expiry_seconds()},
        {"user", consumer_user.to_json_public()},
        {"account", acc.to_json()}
    });
}

server::HttpResponse AuthController::login(const server::HttpRequest& req, const auth::AuthContext&) {
    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (...) {
        return server::HttpResponse::error(400, "Bad Request", "Malformed JSON request body");
    }

    std::string name;
    if (body.contains("name") && body["name"].is_string()) name = body["name"].get<std::string>();
    else if (body.contains("holder_name") && body["holder_name"].is_string()) name = body["holder_name"].get<std::string>();
    else if (body.contains("customer_name") && body["customer_name"].is_string()) name = body["customer_name"].get<std::string>();

    std::string account_number;
    if (body.contains("account_number") && body["account_number"].is_string()) account_number = body["account_number"].get<std::string>();
    else if (body.contains("account_id") && body["account_id"].is_string()) account_number = body["account_id"].get<std::string>();

    std::string username;
    if (body.contains("username") && body["username"].is_string()) username = body["username"].get<std::string>();

    std::string password;
    if (body.contains("password") && body["password"].is_string()) password = body["password"].get<std::string>();

    std::string role_str;
    if (body.contains("role") && body["role"].is_string()) role_str = body["role"].get<std::string>();

    if (password.empty()) {
        return server::HttpResponse::error(400, "Bad Request", "Missing required password");
    }

    std::optional<models::User> user_opt = std::nullopt;

    // Path A: Consumer Login with account_number
    if (!account_number.empty()) {
        user_opt = db_->find_user_by_account_id(account_number);
        if (!user_opt.has_value()) {
            user_opt = db_->find_user_by_username(account_number);
        }
        if (!user_opt.has_value() && !name.empty()) {
            user_opt = db_->find_user_by_username(name);
            if (user_opt.has_value() && user_opt->associated_account_id.value_or("") != account_number) {
                user_opt = std::nullopt;
            }
        }

        if (!user_opt.has_value()) {
            return server::HttpResponse::error(401, "Unauthorized", "Invalid credentials: account not found");
        }

        // Validate name if provided
        if (!name.empty()) {
            bool matches = false;
            if (!user_opt->name.empty() && to_lower_str(user_opt->name) == to_lower_str(name)) {
                matches = true;
            } else if (!user_opt->username.empty() && to_lower_str(user_opt->username) == to_lower_str(name)) {
                matches = true;
            } else if (user_opt->associated_account_id.has_value()) {
                auto acc = db_->find_account_by_id(*user_opt->associated_account_id);
                if (acc.has_value() && to_lower_str(acc->holder_name) == to_lower_str(name)) {
                    matches = true;
                }
            }
            if (!matches) {
                return server::HttpResponse::error(401, "Unauthorized", "Account number and name do not match");
            }
        }
    } else {
        // Path B: Bank Employee or legacy username login
        std::string identifier = !username.empty() ? username : name;
        if (identifier.empty()) {
            return server::HttpResponse::error(400, "Bad Request", "Missing account number or username");
        }

        user_opt = db_->find_user_by_username(identifier);
        if (!user_opt.has_value()) {
            user_opt = db_->find_user_by_account_id(identifier);
        }
        if (!user_opt.has_value()) {
            for (const auto& u : db_->list_users()) {
                if (to_lower_str(u.name) == to_lower_str(identifier)) {
                    user_opt = u;
                    break;
                }
            }
        }

        if (!user_opt.has_value()) {
            return server::HttpResponse::error(401, "Unauthorized", "Invalid credentials: user not found");
        }
    }

    // Role check (if role specified in request)
    if (!role_str.empty()) {
        auto req_role_opt = models::string_to_user_role(role_str);
        if (!req_role_opt.has_value() || user_opt->role != *req_role_opt) {
            return server::HttpResponse::error(401, "Unauthorized", "Invalid credentials or unauthorized role requested");
        }
    }

    // Verify Password Hash
    if (!auth::PasswordHasher::verify_password(password, user_opt->password_hash)) {
        return server::HttpResponse::error(401, "Unauthorized", "Invalid credentials");
    }

    // Generate JWT Token
    auth::JwtTokenClaims claims;
    claims.user_id = user_opt->user_id;
    claims.username = user_opt->username;
    claims.role = models::user_role_to_string(user_opt->role);
    claims.associated_account_id = user_opt->associated_account_id;
    claims.iat = 0;
    claims.exp = 0;

    std::string token = jwt_manager_->create_token(claims);

    nlohmann::json response_payload = {
        {"access_token", token},
        {"token_type", "Bearer"},
        {"expires_in", jwt_manager_->get_default_expiry_seconds()},
        {"user", user_opt->to_json_public()}
    };

    if (user_opt->associated_account_id.has_value()) {
        auto acc = db_->find_account_by_id(*user_opt->associated_account_id);
        if (acc.has_value()) {
            response_payload["account"] = acc->to_json();
        }
    }

    utils::Logger::info("User logged in successfully: " + user_opt->username + " (Role: " + models::user_role_to_string(user_opt->role) + ")");
    return server::HttpResponse::json(200, response_payload);
}

server::HttpResponse AuthController::get_me(const server::HttpRequest&, const auth::AuthContext& auth_ctx) {
    auto user_opt = db_->find_user_by_id(auth_ctx.user_id);
    if (!user_opt.has_value()) {
        return server::HttpResponse::error(404, "Not Found", "User not found");
    }
    return server::HttpResponse::json(200, user_opt->to_json_public());
}

server::HttpResponse AuthController::get_my_account(const server::HttpRequest&, const auth::AuthContext& auth_ctx) {
    if (!auth_ctx.associated_account_id.has_value()) {
        return server::HttpResponse::error(404, "Not Found", "No account associated with this consumer profile");
    }
    auto account_opt = db_->find_account_by_id(*auth_ctx.associated_account_id);
    if (!account_opt.has_value()) {
        return server::HttpResponse::error(404, "Not Found", "Associated account record not found");
    }
    return server::HttpResponse::json(200, account_opt->to_json());
}

} // namespace trustgraph::controllers
