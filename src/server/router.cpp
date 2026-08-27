#include "server/router.hpp"
#include <sstream>

namespace onyx::server {

std::vector<std::string> Router::split_path(const std::string& path) {
    std::vector<std::string> segments;
    std::string seg;
    for (char c : path) {
        if (c == '/') {
            if (!seg.empty()) {
                segments.push_back(seg);
                seg.clear();
            }
        } else {
            seg += c;
        }
    }
    if (!seg.empty()) {
        segments.push_back(seg);
    }
    return segments;
}

void Router::parse_query_string(const std::string& raw_query, QueryParamsMap& query_map) {
    if (raw_query.empty()) return;
    std::istringstream stream(raw_query);
    std::string pair;
    while (std::getline(stream, pair, '&')) {
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            query_map[pair.substr(0, eq)] = pair.substr(eq + 1);
        } else if (!pair.empty()) {
            query_map[pair] = "";
        }
    }
}

Router::Router(std::shared_ptr<auth::RbacMiddleware> rbac_middleware)
    : rbac_middleware_(std::move(rbac_middleware)) {}

void Router::add_route(HttpMethod method, const std::string& path_pattern, auth::RoleRequirement requirement, RouteHandler handler) {
    Route route;
    route.method = method;
    route.pattern = path_pattern;
    route.pattern_segments = split_path(path_pattern);
    route.requirement = requirement;
    route.handler = std::move(handler);
    routes_.push_back(std::move(route));
}

bool Router::match_route(const Route& route, const std::vector<std::string>& path_segments, PathParamsMap& out_params) const {
    if (route.pattern_segments.size() != path_segments.size()) {
        return false;
    }

    out_params.clear();
    for (size_t i = 0; i < route.pattern_segments.size(); ++i) {
        const auto& r_seg = route.pattern_segments[i];
        const auto& p_seg = path_segments[i];

        if (!r_seg.empty() && r_seg[0] == ':') {
            std::string param_name = r_seg.substr(1);
            out_params[param_name] = p_seg;
        } else if (r_seg != p_seg) {
            return false;
        }
    }

    return true;
}

HttpResponse Router::handle_request(HttpRequest req) const {
    // Handle CORS Preflight
    if (req.method == HttpMethod::OPTIONS) {
        HttpResponse res;
        res.status_code = 204;
        res.status_text = "No Content";
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        res.set_header("Access-Control-Max-Age", "86400");
        return res;
    }

    // Separate raw path and query if not separated
    size_t q_pos = req.path.find('?');
    if (q_pos != std::string::npos) {
        req.raw_query = req.path.substr(q_pos + 1);
        req.path = req.path.substr(0, q_pos);
        parse_query_string(req.raw_query, req.query_params);
    }

    auto path_segments = split_path(req.path);
    bool path_matched_any_method = false;

    for (const auto& route : routes_) {
        PathParamsMap params;
        if (match_route(route, path_segments, params)) {
            path_matched_any_method = true;
            if (route.method == req.method) {
                req.path_params = std::move(params);

                // Run RBAC / Auth middleware
                auto [auth_ctx, error_resp] = rbac_middleware_->authenticate_and_authorize(req, route.requirement);
                if (error_resp.has_value()) {
                    return *error_resp;
                }

                try {
                    return route.handler(req, auth_ctx.value_or(auth::AuthContext{}));
                } catch (const std::exception& ex) {
                    return HttpResponse::error(500, "Internal Server Error", std::string("Unhandled exception: ") + ex.what());
                } catch (...) {
                    return HttpResponse::error(500, "Internal Server Error", "Unhandled unknown exception");
                }
            }
        }
    }

    if (path_matched_any_method) {
        return HttpResponse::error(405, "Method Not Allowed", "Method " + http_method_to_string(req.method) + " is not allowed for " + req.path);
    }

    return HttpResponse::error(404, "Not Found", "Endpoint " + req.path + " does not exist on ONYX API");
}

} // namespace onyx::server
