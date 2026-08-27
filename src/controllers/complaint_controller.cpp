#include "controllers/complaint_controller.hpp"
#include "utils/crypto_utils.hpp"
#include "utils/logger.hpp"
#include "utils/json.hpp"
#include <algorithm>
#include <chrono>

using json = nlohmann::json;

namespace onyx::controllers {

ComplaintController::ComplaintController(std::shared_ptr<db::InMemoryStore> db)
    : db_(std::move(db)) {}

void ComplaintController::register_routes(std::shared_ptr<server::Router> router) {
    // 1. File Complaint (Protected: CONSUMER_ONLY)
    router->post("/api/v1/complaints", auth::RoleRequirement::CONSUMER_ONLY,
        [this](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
            return this->file_complaint(req, auth_ctx);
        });

    // 2. Triage List (Protected: BANK_EMPLOYEE_ONLY)
    router->get("/api/v1/complaints", auth::RoleRequirement::BANK_EMPLOYEE_ONLY,
        [this](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
            return this->list_complaints(req, auth_ctx);
        });

    // 3. Update Status (Protected: BANK_EMPLOYEE_ONLY)
    router->put("/api/v1/complaints/:complaint_id/status", auth::RoleRequirement::BANK_EMPLOYEE_ONLY,
        [this](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
            return this->update_complaint_status(req, auth_ctx);
        });
}

server::HttpResponse ComplaintController::file_complaint(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const {
    if (!auth_ctx.associated_account_id.has_value() || auth_ctx.associated_account_id->empty()) {
        return server::HttpResponse::error(403, "Forbidden", "Consumer profile has no associated bank account");
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        return server::HttpResponse::error(400, "Bad Request", "Malformed JSON request body");
    }

    if (!body.contains("suspect_upi_id") || !body["suspect_upi_id"].is_string() ||
        !body.contains("scam_category") || !body["scam_category"].is_string()) {
        return server::HttpResponse::error(400, "Bad Request", "Missing required fields: suspect_upi_id, scam_category");
    }

    std::string suspect_upi = body["suspect_upi_id"].get<std::string>();
    std::string scam_category = body["scam_category"].get<std::string>();
    std::string description = body.value("description", "");

    // Resolve suspect Account (accepts UPI ID or Account ID)
    auto suspect_acc_opt = db_->find_account_by_upi(suspect_upi);
    if (!suspect_acc_opt.has_value()) {
        suspect_acc_opt = db_->find_account_by_id(suspect_upi);
    }
    if (!suspect_acc_opt.has_value()) {
        return server::HttpResponse::error(404, "Not Found", "Suspect UPI ID not found in directory: " + suspect_upi);
    }

    // Process Transaction Reference: Support both internal and external transactions
    std::string tx_id;
    double amount = body.value("amount", 0.0);
    std::string timestamp;

    if (body.contains("transaction_id") && body["transaction_id"].is_string() && !body["transaction_id"].get<std::string>().empty()) {
        tx_id = body["transaction_id"].get<std::string>();
        auto tx_opt = db_->find_transaction_by_id(tx_id);
        if (tx_opt.has_value()) {
            // Verify internal transaction ownership
            if (tx_opt->sender_account_id != *auth_ctx.associated_account_id) {
                return server::HttpResponse::error(403, "Forbidden", "Access denied: You can only file complaints for outbound transfers from your own account");
            }
            if (suspect_acc_opt->account_id != tx_opt->receiver_account_id) {
                return server::HttpResponse::error(400, "Bad Request", "Suspect UPI ID does not match recipient of the transaction");
            }
            if (amount <= 0.0) {
                amount = tx_opt->amount;
            }
            timestamp = tx_opt->timestamp;
        }
    }

    if (tx_id.empty()) {
        std::string rand_ref = crypto::get_random_hex(4);
        std::transform(rand_ref.begin(), rand_ref.end(), rand_ref.begin(), ::toupper);
        tx_id = "EXT-TXN-" + rand_ref;
    }

    if (timestamp.empty()) {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now_c));
        timestamp = std::string(buf);
    }

    // Create Complaint Record
    std::string cmp_rand = crypto::get_random_hex(2);
    std::transform(cmp_rand.begin(), cmp_rand.end(), cmp_rand.begin(), ::toupper);
    std::string cmp_id = "CMP-2026-" + cmp_rand;

    models::FraudComplaint complaint;
    complaint.complaint_id = cmp_id;
    complaint.complainant_account_id = *auth_ctx.associated_account_id;
    complaint.suspect_account_id = suspect_acc_opt->account_id;
    complaint.transaction_id = tx_id;
    complaint.amount = amount;
    complaint.scam_category = scam_category;
    complaint.description = description;
    complaint.status = "SUBMITTED";
    complaint.created_at = timestamp;

    db_->create_complaint(complaint);

    // Auto-Taint & Dynamic Flagging:
    // Adding a complaint instantly increments the suspect's risk_score (+25.0).
    // If active complaints >= 2 or risk_score >= 70.0, transition to FLAGGED.
    size_t active_complaints = db_->count_complaints_for_suspect(suspect_acc_opt->account_id);
    models::AccountStatus new_status = suspect_acc_opt->status;
    if (new_status != models::AccountStatus::FROZEN) {
        if (active_complaints >= 2 || (suspect_acc_opt->risk_score + 25.0) >= 70.0) {
            new_status = models::AccountStatus::FLAGGED;
        }
    }

    db_->apply_taint_update(suspect_acc_opt->account_id, 25.0, new_status);
    utils::Logger::warn("Auto-taint feedback applied: Suspect " + suspect_acc_opt->account_id +
                        " risk score incremented (+25.0), active complaints = " + std::to_string(active_complaints) +
                        ", status = " + models::account_status_to_string(new_status));

    json response_json = {
        {"complaint_id", complaint.complaint_id},
        {"status", complaint.status},
        {"message", "Complaint logged in Bank Fraud Registry. Taint score updated on recipient node."},
        {"timestamp", complaint.created_at}
    };

    return server::HttpResponse::json(201, response_json);
}

server::HttpResponse ComplaintController::list_complaints(const server::HttpRequest& req, const auth::AuthContext&) const {
    std::optional<std::string> status_filter = std::nullopt;
    auto it_status = req.query_params.find("status");
    if (it_status != req.query_params.end() && !it_status->second.empty()) {
        status_filter = it_status->second;
    }

    size_t limit = 50;
    auto it_limit = req.query_params.find("limit");
    if (it_limit != req.query_params.end() && !it_limit->second.empty()) {
        try {
            limit = std::stoul(it_limit->second);
        } catch (...) {
            limit = 50;
        }
    }

    auto complaints = db_->list_complaints(status_filter, limit);
    json complaint_list = json::array();
    for (const auto& c : complaints) {
        complaint_list.push_back(c.to_json());
    }

    return server::HttpResponse::json(200, {
        {"total", complaint_list.size()},
        {"complaints", complaint_list}
    });
}

server::HttpResponse ComplaintController::update_complaint_status(const server::HttpRequest& req, const auth::AuthContext&) const {
    std::string complaint_id = req.path_params.at("complaint_id");
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        return server::HttpResponse::error(400, "Bad Request", "Malformed JSON request body");
    }

    if (!body.contains("status") || !body["status"].is_string()) {
        return server::HttpResponse::error(400, "Bad Request", "Missing 'status' field in request body");
    }

    std::string new_status = body["status"].get<std::string>();
    auto existing = db_->find_complaint_by_id(complaint_id);
    if (!existing.has_value()) {
        return server::HttpResponse::error(404, "Not Found", "Complaint not found: " + complaint_id);
    }

    db_->update_complaint_status(complaint_id, new_status);
    return server::HttpResponse::json(200, {
        {"complaint_id", complaint_id},
        {"status", new_status},
        {"message", "Complaint triage status updated successfully."}
    });
}

} // namespace onyx::controllers
