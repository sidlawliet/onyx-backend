#include <cassert>
#include <iostream>
#include <memory>
#include "db/in_memory_store.hpp"
#include "auth/jwt_manager.hpp"
#include "auth/rbac_middleware.hpp"
#include "server/router.hpp"
#include "utils/json.hpp"

using json = nlohmann::json;
using namespace trustgraph;

void test_complaints_and_taint_engine() {
    std::cout << "[TEST] Running test_complaints_and_taint_engine..." << std::endl;

    auto db = std::make_shared<db::InMemoryStore>();
    std::string secret = "test_complaints_secret_key!";
    auto jwt_manager = std::make_shared<auth::JwtManager>(secret, 86400);
    auto rbac_middleware = std::make_shared<auth::RbacMiddleware>(jwt_manager);
    auto router = std::make_shared<server::Router>(rbac_middleware);

    // Register complaints routes
    router->post("/api/v1/complaints", auth::RoleRequirement::CONSUMER_ONLY, [db](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
        if (!auth_ctx.associated_account_id.has_value() || auth_ctx.associated_account_id->empty()) {
            return server::HttpResponse::error(403, "Forbidden", "Consumer profile has no associated bank account");
        }

        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            return server::HttpResponse::error(400, "Bad Request", "Malformed JSON");
        }

        std::string tx_id = body.value("transaction_id", "");
        std::string suspect_upi = body.value("suspect_upi_id", "");
        std::string scam_cat = body.value("scam_category", "");
        std::string desc = body.value("description", "");

        auto tx_opt = db->find_transaction_by_id(tx_id);
        if (!tx_opt.has_value()) {
            return server::HttpResponse::error(404, "Not Found", "Transaction not found");
        }

        if (tx_opt->sender_account_id != *auth_ctx.associated_account_id) {
            return server::HttpResponse::error(403, "Forbidden", "Access denied: unowned transaction");
        }

        auto suspect_acc_opt = db->find_account_by_upi(suspect_upi);
        if (!suspect_acc_opt.has_value() || suspect_acc_opt->account_id != tx_opt->receiver_account_id) {
            return server::HttpResponse::error(400, "Bad Request", "Suspect UPI does not match recipient");
        }

        models::FraudComplaint cmp;
        cmp.complaint_id = "CMP-TEST-" + std::to_string(db->list_complaints().size() + 1);
        cmp.complainant_account_id = *auth_ctx.associated_account_id;
        cmp.suspect_account_id = suspect_acc_opt->account_id;
        cmp.transaction_id = tx_id;
        cmp.amount = tx_opt->amount;
        cmp.scam_category = scam_cat;
        cmp.description = desc;
        cmp.status = "SUBMITTED";
        cmp.created_at = tx_opt->timestamp;
        db->create_complaint(cmp);

        // Auto-taint feedback
        size_t active_complaints = db->count_complaints_for_suspect(suspect_acc_opt->account_id);
        if (active_complaints >= 2) {
            db->apply_taint_update(suspect_acc_opt->account_id, 25.0, models::AccountStatus::FLAGGED);
        }

        return server::HttpResponse::json(201, {
            {"complaint_id", cmp.complaint_id},
            {"status", cmp.status},
            {"message", "Complaint logged in Bank Fraud Registry. Taint score updated on recipient node."},
            {"timestamp", cmp.created_at}
        });
    });

    router->get("/api/v1/complaints", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [db](const server::HttpRequest& req, const auth::AuthContext&) {
        std::optional<std::string> status_filter = std::nullopt;
        auto it = req.query_params.find("status");
        if (it != req.query_params.end() && !it->second.empty()) {
            status_filter = it->second;
        }

        auto complaints = db->list_complaints(status_filter, 50);
        json list = json::array();
        for (const auto& c : complaints) {
            list.push_back(c.to_json());
        }
        return server::HttpResponse::json(200, {{"total", list.size()}, {"complaints", list}});
    });

    router->put("/api/v1/complaints/:complaint_id/status", auth::RoleRequirement::BANK_EMPLOYEE_ONLY, [db](const server::HttpRequest& req, const auth::AuthContext&) {
        std::string cmp_id = req.path_params.at("complaint_id");
        json body = json::parse(req.body);
        std::string new_status = body.value("status", "");
        db->update_complaint_status(cmp_id, new_status);
        return server::HttpResponse::json(200, {{"complaint_id", cmp_id}, {"status", new_status}});
    });

    // Create tokens
    auth::JwtTokenClaims consumer_claims;
    consumer_claims.user_id = "USR-8819A";
    consumer_claims.username = "siddharth_k";
    consumer_claims.role = "CONSUMER";
    consumer_claims.associated_account_id = "ACC-7A1B8C9D";
    std::string consumer_token = jwt_manager->create_token(consumer_claims);

    auth::JwtTokenClaims other_consumer_claims;
    other_consumer_claims.user_id = "USR-OTHER";
    other_consumer_claims.username = "other_user";
    other_consumer_claims.role = "CONSUMER";
    other_consumer_claims.associated_account_id = "ACC-OTHER-99";
    std::string other_consumer_token = jwt_manager->create_token(other_consumer_claims);

    auth::JwtTokenClaims bank_claims;
    bank_claims.user_id = "USR-BANK-001";
    bank_claims.username = "analyst_raj";
    bank_claims.role = "BANK_EMPLOYEE";
    std::string bank_token = jwt_manager->create_token(bank_claims);

    // 1. Consumer files valid complaint on TXN-88F19280AA
    server::HttpRequest cmp1_req;
    cmp1_req.method = server::HttpMethod::POST;
    cmp1_req.path = "/api/v1/complaints";
    cmp1_req.headers["Authorization"] = "Bearer " + consumer_token;
    cmp1_req.body = "{\"transaction_id\":\"TXN-88F19280AA\",\"suspect_upi_id\":\"invest_guru@ybl\",\"scam_category\":\"TASK_JOB_SCAM\",\"description\":\"Fake Telegram job\"}";

    auto cmp1_res = router->handle_request(cmp1_req);
    assert(cmp1_res.status_code == 201);
    auto cmp1_json = json::parse(cmp1_res.body);
    assert(cmp1_json["status"] == "SUBMITTED");
    assert(cmp1_json.contains("complaint_id"));
    std::string cmp1_id = cmp1_json["complaint_id"].get<std::string>();

    // 2. Unowned transaction complaint -> 403 Forbidden
    server::HttpRequest unauth_cmp_req;
    unauth_cmp_req.method = server::HttpMethod::POST;
    unauth_cmp_req.path = "/api/v1/complaints";
    unauth_cmp_req.headers["Authorization"] = "Bearer " + other_consumer_token;
    unauth_cmp_req.body = "{\"transaction_id\":\"TXN-88F19280AA\",\"suspect_upi_id\":\"invest_guru@ybl\",\"scam_category\":\"TASK_JOB_SCAM\"}";
    auto unauth_cmp_res = router->handle_request(unauth_cmp_req);
    assert(unauth_cmp_res.status_code == 403);

    // 3. Suspect mismatch -> 400 Bad Request
    server::HttpRequest mismatch_cmp_req;
    mismatch_cmp_req.method = server::HttpMethod::POST;
    mismatch_cmp_req.path = "/api/v1/complaints";
    mismatch_cmp_req.headers["Authorization"] = "Bearer " + consumer_token;
    mismatch_cmp_req.body = "{\"transaction_id\":\"TXN-88F19280AA\",\"suspect_upi_id\":\"mule_wallet@paytm\",\"scam_category\":\"TASK_JOB_SCAM\"}";
    auto mismatch_cmp_res = router->handle_request(mismatch_cmp_req);
    assert(mismatch_cmp_res.status_code == 400);

    // 4. Test Auto-Taint feedback:
    // Create a 2nd transaction from Siddharth to invest_guru and file 2nd complaint
    models::Transaction tx2;
    tx2.transaction_id = "TXN-SECOND-TRANSFER";
    tx2.sender_account_id = "ACC-7A1B8C9D";
    tx2.receiver_account_id = "ACC-9F2E4A10";
    tx2.amount = 10000.00;
    tx2.status = models::TransactionStatus::COMPLETED;
    tx2.timestamp = "2026-08-25T14:45:00Z";
    db->create_transaction(tx2);

    auto suspect_before = db->find_account_by_upi("invest_guru@ybl");
    double suspect_score_before = suspect_before->risk_score;

    server::HttpRequest cmp2_req;
    cmp2_req.method = server::HttpMethod::POST;
    cmp2_req.path = "/api/v1/complaints";
    cmp2_req.headers["Authorization"] = "Bearer " + consumer_token;
    cmp2_req.body = "{\"transaction_id\":\"TXN-SECOND-TRANSFER\",\"suspect_upi_id\":\"invest_guru@ybl\",\"scam_category\":\"INVESTMENT_FRAUD\",\"description\":\"Refused withdrawal\"}";

    auto cmp2_res = router->handle_request(cmp2_req);
    assert(cmp2_res.status_code == 201);

    // Verify auto-taint escalation (+25.0 risk score and FLAGGED status)
    auto suspect_after = db->find_account_by_upi("invest_guru@ybl");
    assert(suspect_after->status == models::AccountStatus::FLAGGED);
    assert(suspect_after->risk_score >= std::min(100.0, suspect_score_before + 25.0));

    // 5. Bank Employee Triage List
    server::HttpRequest triage_req;
    triage_req.method = server::HttpMethod::GET;
    triage_req.path = "/api/v1/complaints";
    triage_req.headers["Authorization"] = "Bearer " + bank_token;
    auto triage_res = router->handle_request(triage_req);
    assert(triage_res.status_code == 200);
    auto triage_json = json::parse(triage_res.body);
    assert(triage_json["total"] == 2);

    // 6. Consumer denied triage access
    server::HttpRequest consumer_triage_req;
    consumer_triage_req.method = server::HttpMethod::GET;
    consumer_triage_req.path = "/api/v1/complaints";
    consumer_triage_req.headers["Authorization"] = "Bearer " + consumer_token;
    auto consumer_triage_res = router->handle_request(consumer_triage_req);
    assert(consumer_triage_res.status_code == 403);

    // 7. Bank Employee updates complaint status
    server::HttpRequest update_status_req;
    update_status_req.method = server::HttpMethod::PUT;
    update_status_req.path = "/api/v1/complaints/" + cmp1_id + "/status";
    update_status_req.headers["Authorization"] = "Bearer " + bank_token;
    update_status_req.body = "{\"status\":\"UNDER_INVESTIGATION\"}";
    auto update_status_res = router->handle_request(update_status_req);
    assert(update_status_res.status_code == 200);

    auto updated_cmp = db->find_complaint_by_id(cmp1_id);
    assert(updated_cmp.has_value());
    assert(updated_cmp->status == "UNDER_INVESTIGATION");

    std::cout << "  -> test_complaints_and_taint_engine passed!" << std::endl;
}

int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << "   RUNNING COMPLAINTS & TAINT TEST SUITE  " << std::endl;
    std::cout << "==========================================" << std::endl;

    test_complaints_and_taint_engine();

    std::cout << "All Complaints & Taint tests passed successfully!" << std::endl;
    return 0;
}
