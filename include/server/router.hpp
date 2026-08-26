#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include "server/http_types.hpp"
#include "auth/rbac_middleware.hpp"

namespace trustgraph::server {

using RouteHandler = std::function<HttpResponse(const HttpRequest&, const auth::AuthContext&)>;

struct Route {
    HttpMethod method;
    std::string pattern;
    std::vector<std::string> pattern_segments;
    auth::RoleRequirement requirement;
    RouteHandler handler;
};

class Router {
public:
    explicit Router(std::shared_ptr<auth::RbacMiddleware> rbac_middleware);

    void add_route(HttpMethod method, const std::string& path_pattern, auth::RoleRequirement requirement, RouteHandler handler);

    // Convenience methods
    void get(const std::string& pattern, auth::RoleRequirement requirement, RouteHandler handler) {
        add_route(HttpMethod::GET, pattern, requirement, std::move(handler));
    }

    void post(const std::string& pattern, auth::RoleRequirement requirement, RouteHandler handler) {
        add_route(HttpMethod::POST, pattern, requirement, std::move(handler));
    }

    void put(const std::string& pattern, auth::RoleRequirement requirement, RouteHandler handler) {
        add_route(HttpMethod::PUT, pattern, requirement, std::move(handler));
    }

    void delete_method(const std::string& pattern, auth::RoleRequirement requirement, RouteHandler handler) {
        add_route(HttpMethod::DELETE_METHOD, pattern, requirement, std::move(handler));
    }

    HttpResponse handle_request(HttpRequest req) const;

    static std::vector<std::string> split_path(const std::string& path);
    static void parse_query_string(const std::string& raw_query, QueryParamsMap& query_map);

private:
    std::shared_ptr<auth::RbacMiddleware> rbac_middleware_;
    std::vector<Route> routes_;

    bool match_route(const Route& route, const std::vector<std::string>& path_segments, PathParamsMap& out_params) const;
};

} // namespace trustgraph::server
