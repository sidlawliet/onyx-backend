#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include "server/router.hpp"

namespace onyx::server {

class HttpServer {
public:
    HttpServer(std::string host, int port, std::shared_ptr<Router> router);
    ~HttpServer();

    bool start();
    void stop();
    bool is_running() const { return running_; }

    const std::string& host() const { return host_; }
    int port() const { return port_; }

private:
    std::string host_;
    int port_;
    std::shared_ptr<Router> router_;
    std::atomic<bool> running_{false};
    std::shared_ptr<std::atomic<size_t>> active_workers_;
    std::thread server_thread_;

    void run_event_loop();
    static void process_client_socket(uintptr_t client_fd, std::shared_ptr<Router> router, std::shared_ptr<std::atomic<size_t>> active_workers);
    static HttpRequest parse_raw_http(const std::string& raw_data);
};

} // namespace onyx::server
