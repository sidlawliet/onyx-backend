#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include "utils/json.hpp"

namespace trustgraph::server {

enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE_METHOD,
    OPTIONS,
    PATCH,
    UNKNOWN
};

inline std::string http_method_to_string(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET: return "GET";
        case HttpMethod::POST: return "POST";
        case HttpMethod::PUT: return "PUT";
        case HttpMethod::DELETE_METHOD: return "DELETE";
        case HttpMethod::OPTIONS: return "OPTIONS";
        case HttpMethod::PATCH: return "PATCH";
        case HttpMethod::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

inline HttpMethod string_to_http_method(const std::string& str) {
    if (str == "GET") return HttpMethod::GET;
    if (str == "POST") return HttpMethod::POST;
    if (str == "PUT") return HttpMethod::PUT;
    if (str == "DELETE") return HttpMethod::DELETE_METHOD;
    if (str == "OPTIONS") return HttpMethod::OPTIONS;
    if (str == "PATCH") return HttpMethod::PATCH;
    return HttpMethod::UNKNOWN;
}

struct CaseInsensitiveHash {
    size_t operator()(const std::string& str) const {
        size_t hash = 0;
        for (char c : str) {
            hash = hash * 31 + std::tolower(static_cast<unsigned char>(c));
        }
        return hash;
    }
};

struct CaseInsensitiveEqual {
    bool operator()(const std::string& a, const std::string& b) const {
        if (a.size() != b.size()) return false;
        return std::equal(a.begin(), a.end(), b.begin(), [](char ca, char cb) {
            return std::tolower(static_cast<unsigned char>(ca)) == std::tolower(static_cast<unsigned char>(cb));
        });
    }
};

using HeaderMap = std::unordered_map<std::string, std::string, CaseInsensitiveHash, CaseInsensitiveEqual>;
using QueryParamsMap = std::unordered_map<std::string, std::string>;
using PathParamsMap = std::unordered_map<std::string, std::string>;

struct HttpRequest {
    HttpMethod method = HttpMethod::GET;
    std::string path;
    std::string raw_query;
    QueryParamsMap query_params;
    PathParamsMap path_params;
    HeaderMap headers;
    std::string body;

    std::string get_header(const std::string& name, const std::string& default_val = "") const {
        auto it = headers.find(name);
        return it != headers.end() ? it->second : default_val;
    }
};

struct HttpResponse {
    int status_code = 200;
    std::string status_text = "OK";
    HeaderMap headers;
    std::string body;

    void set_header(const std::string& key, const std::string& value) {
        headers[key] = value;
    }

    static HttpResponse json(int code, const nlohmann::json& payload, const std::string& status_text = "OK") {
        HttpResponse res;
        res.status_code = code;
        res.status_text = status_text;
        res.set_header("Content-Type", "application/json; charset=utf-8");
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        res.body = payload.dump(2);
        return res;
    }

    static HttpResponse error(int code, const std::string& error_title, const std::string& message) {
        nlohmann::json payload = {
            {"error", error_title},
            {"message", message},
            {"status_code", code}
        };
        std::string status_text = "Error";
        if (code == 400) status_text = "Bad Request";
        else if (code == 401) status_text = "Unauthorized";
        else if (code == 403) status_text = "Forbidden";
        else if (code == 404) status_text = "Not Found";
        else if (code == 422) status_text = "Unprocessable Entity";
        else if (code == 500) status_text = "Internal Server Error";

        return HttpResponse::json(code, payload, status_text);
    }
};

} // namespace trustgraph::server
