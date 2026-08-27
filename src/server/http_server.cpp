#include "server/http_server.hpp"
#include "utils/logger.hpp"
#include <sstream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define closesocket close
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
typedef int SOCKET;
#endif

namespace onyx::server {

namespace {
bool init_sockets() {
#ifdef _WIN32
    WSADATA wsaData;
    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != 0) {
        utils::Logger::error("WSAStartup failed with error: " + std::to_string(res));
        return false;
    }
#endif
    return true;
}

void cleanup_sockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}
} // anonymous namespace

HttpServer::HttpServer(std::string host, int port, std::shared_ptr<Router> router)
    : host_(std::move(host)), port_(port), router_(std::move(router)),
      active_workers_(std::make_shared<std::atomic<size_t>>(0)) {
    init_sockets();
}

HttpServer::~HttpServer() {
    stop();
    cleanup_sockets();
}

bool HttpServer::start() {
    if (running_) return true;
    running_ = true;

    server_thread_ = std::thread(&HttpServer::run_event_loop, this);
    return true;
}

void HttpServer::stop() {
    if (!running_) return;
    running_ = false;

    // Connect a dummy socket to unblock accept if necessary
    SOCKET dummy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (dummy_sock != INVALID_SOCKET) {
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port_);
        inet_pton(AF_INET, host_ == "0.0.0.0" ? "127.0.0.1" : host_.c_str(), &server_addr.sin_addr);
        connect(dummy_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
        closesocket(dummy_sock);
    }

    if (server_thread_.joinable()) {
        server_thread_.join();
    }

    // Wait up to 300ms for in-flight client workers to complete
    int wait_cycles = 0;
    while (active_workers_ && active_workers_->load() > 0 && wait_cycles < 15) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        wait_cycles++;
    }

    utils::Logger::info("ONYX HTTP Server stopped gracefully.");
}

HttpRequest HttpServer::parse_raw_http(const std::string& raw_data) {
    HttpRequest req;
    size_t header_end = raw_data.find("\r\n\r\n");
    std::string headers_part;
    std::string body_part;

    if (header_end != std::string::npos) {
        headers_part = raw_data.substr(0, header_end);
        body_part = raw_data.substr(header_end + 4);
    } else {
        headers_part = raw_data;
    }

    std::istringstream stream(headers_part);
    std::string request_line;
    if (std::getline(stream, request_line)) {
        if (!request_line.empty() && request_line.back() == '\r') {
            request_line.pop_back();
        }
        std::istringstream line_stream(request_line);
        std::string method_str, path_str, version_str;
        line_stream >> method_str >> path_str >> version_str;
        req.method = string_to_http_method(method_str);
        req.path = path_str;
    }

    std::string header_line;
    while (std::getline(stream, header_line)) {
        if (!header_line.empty() && header_line.back() == '\r') {
            header_line.pop_back();
        }
        size_t colon_pos = header_line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = header_line.substr(0, colon_pos);
            std::string val = header_line.substr(colon_pos + 1);
            // Trim leading spaces in val
            size_t first_non_space = val.find_first_not_of(" \t");
            if (first_non_space != std::string::npos) {
                val = val.substr(first_non_space);
            }
            req.headers[key] = val;
        }
    }

    req.body = body_part;
    return req;
}

void HttpServer::process_client_socket(uintptr_t client_fd, std::shared_ptr<Router> router, std::shared_ptr<std::atomic<size_t>> active_workers) {
    struct WorkerGuard {
        std::shared_ptr<std::atomic<size_t>> counter;
        explicit WorkerGuard(std::shared_ptr<std::atomic<size_t>> c) : counter(std::move(c)) {
            if (counter) (*counter)++;
        }
        ~WorkerGuard() {
            if (counter) (*counter)--;
        }
    } guard(active_workers);

    SOCKET sock = static_cast<SOCKET>(client_fd);

    std::string raw_buffer;
    char buffer[4096];
    int bytes_read = 0;
    size_t expected_total_len = 0;
    bool headers_parsed = false;

    while (true) {
        bytes_read = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_read <= 0) {
            break;
        }
        raw_buffer.append(buffer, bytes_read);

        if (!headers_parsed) {
            size_t header_end = raw_buffer.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                headers_parsed = true;
                // Check Content-Length
                std::string headers = raw_buffer.substr(0, header_end);
                std::string search_str = "Content-Length:";
                size_t pos = headers.find(search_str);
                if (pos == std::string::npos) {
                    search_str = "content-length:";
                    pos = headers.find(search_str);
                }
                if (pos != std::string::npos) {
                    size_t line_end = headers.find("\r\n", pos);
                    std::string len_str = headers.substr(pos + search_str.length(), line_end - (pos + search_str.length()));
                    size_t content_len = std::stoul(len_str);
                    expected_total_len = (header_end + 4) + content_len;
                } else {
                    expected_total_len = header_end + 4;
                }
            }
        }

        if (headers_parsed && raw_buffer.size() >= expected_total_len) {
            break;
        }
    }

    if (!raw_buffer.empty() && router) {
        HttpRequest req = parse_raw_http(raw_buffer);
        HttpResponse res = router->handle_request(std::move(req));

        std::ostringstream response_stream;
        response_stream << "HTTP/1.1 " << res.status_code << " " << res.status_text << "\r\n";
        response_stream << "Content-Length: " << res.body.size() << "\r\n";
        response_stream << "Connection: close\r\n";

        for (const auto& [k, v] : res.headers) {
            response_stream << k << ": " << v << "\r\n";
        }
        response_stream << "\r\n" << res.body;

        std::string response_data = response_stream.str();
        send(sock, response_data.c_str(), static_cast<int>(response_data.size()), 0);
    }

    closesocket(sock);
}

void HttpServer::run_event_loop() {
    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd == INVALID_SOCKET) {
        utils::Logger::error("Failed to create socket!");
        running_ = false;
        return;
    }

    int opt = 1;
#ifdef _WIN32
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port_);
    if (host_ == "0.0.0.0" || host_.empty()) {
        address.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, host_.c_str(), &address.sin_addr);
    }

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) == SOCKET_ERROR) {
        utils::Logger::error("Failed to bind socket to " + host_ + ":" + std::to_string(port_));
        closesocket(server_fd);
        running_ = false;
        return;
    }

    if (listen(server_fd, SOMAXCONN) == SOCKET_ERROR) {
        utils::Logger::error("Failed to listen on socket");
        closesocket(server_fd);
        running_ = false;
        return;
    }

    utils::Logger::info("ONYX C++ Engine listening on http://" + host_ + ":" + std::to_string(port_));

    while (running_) {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        SOCKET client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);

        if (client_fd == INVALID_SOCKET) {
            if (!running_) break;
            continue;
        }

        if (!running_) {
            closesocket(client_fd);
            break;
        }

        // Spawn async worker with shared_ptr to router (guarantees lifetime without dangling this)
        auto router = router_;
        auto workers = active_workers_;
        std::thread([client_fd, router, workers]() {
            process_client_socket(static_cast<uintptr_t>(client_fd), router, workers);
        }).detach();
    }

    closesocket(server_fd);
}

} // namespace onyx::server
