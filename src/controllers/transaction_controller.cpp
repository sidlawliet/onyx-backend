#include "controllers/transaction_controller.hpp"
#include "engine/fraud_engine.hpp"
#include "utils/logger.hpp"
#include "utils/json.hpp"

using json = nlohmann::json;

namespace trustgraph::controllers {

TransactionController::TransactionController(std::shared_ptr<db::InMemoryStore> db)
    : db_(std::move(db)) {}

void TransactionController::register_routes(std::shared_ptr<server::Router> router) {
    // 1. Transaction Flag Details
    router->get("/api/v1/transactions/:transaction_id/flag-details", auth::RoleRequirement::ANY_AUTHENTICATED,
        [this](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
            return this->get_flag_details(req, auth_ctx);
        });

    // 2. Transaction List
    router->get("/api/v1/transactions", auth::RoleRequirement::ANY_AUTHENTICATED,
        [this](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
            return this->list_transactions(req, auth_ctx);
        });

    // 3. Single Transaction Lookup
    router->get("/api/v1/transactions/:transaction_id", auth::RoleRequirement::ANY_AUTHENTICATED,
        [this](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
            return this->get_transaction(req, auth_ctx);
        });

    // 4. Decoupled Payment Simulation
    router->post("/api/v1/transactions", auth::RoleRequirement::ANY_AUTHENTICATED,
        [this](const server::HttpRequest& req, const auth::AuthContext& auth_ctx) {
            return this->execute_transaction(req, auth_ctx);
        });
}

server::HttpResponse TransactionController::get_flag_details(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const {
    std::string tx_id = req.path_params.at("transaction_id");
    auto tx_opt = db_->find_transaction_by_id(tx_id);
    if (!tx_opt.has_value()) {
        return server::HttpResponse::error(404, "Not Found", "Transaction not found: " + tx_id);
    }

    // Ownership authorization check for consumer
    if (auth_ctx.is_consumer()) {
        if (!auth_ctx.associated_account_id.has_value() ||
            (tx_opt->sender_account_id != *auth_ctx.associated_account_id &&
             tx_opt->receiver_account_id != *auth_ctx.associated_account_id)) {
            return server::HttpResponse::error(403, "Forbidden", "Access denied: You do not have permission to view flag details for this transaction");
        }
    }

    auto flag_opt = db_->find_flag_by_transaction_id(tx_id);
    if (!flag_opt.has_value()) {
        json clean_response = {
            {"transaction_id", tx_opt->transaction_id},
            {"amount", tx_opt->amount},
            {"timestamp", tx_opt->timestamp},
            {"status", models::transaction_status_to_string(tx_opt->status)},
            {"risk_score", 0.0},
            {"risk_level", "LOW"},
            {"explanation_title", "Standard Clean Transfer"},
            {"warning_reasons", json::array({"Transaction passed all security heuristics with no anomaly detected."})},
            {"recommended_action", "Transaction verified safe."}
        };
        return server::HttpResponse::json(200, clean_response);
    }

    json flag_response = {
        {"transaction_id", tx_opt->transaction_id},
        {"amount", tx_opt->amount},
        {"timestamp", tx_opt->timestamp},
        {"status", models::transaction_status_to_string(tx_opt->status)},
        {"risk_score", flag_opt->risk_score},
        {"risk_level", flag_opt->risk_level},
        {"explanation_title", flag_opt->explanation_title},
        {"warning_reasons", flag_opt->reasons},
        {"recommended_action", flag_opt->recommended_action}
    };

    return server::HttpResponse::json(200, flag_response);
}

server::HttpResponse TransactionController::list_transactions(const server::HttpRequest&, const auth::AuthContext& auth_ctx) const {
    std::vector<models::Transaction> txs;
    if (auth_ctx.is_consumer()) {
        if (auth_ctx.associated_account_id.has_value()) {
            txs = db_->find_transactions_by_account(*auth_ctx.associated_account_id);
        }
    } else {
        txs = db_->list_transactions();
    }

    json tx_list = json::array();
    for (const auto& tx : txs) {
        json item = tx.to_json();
        auto flag_opt = db_->find_flag_by_transaction_id(tx.transaction_id);
        if (flag_opt.has_value()) {
            item["flag"] = flag_opt->to_json();
        }
        tx_list.push_back(item);
    }

    return server::HttpResponse::json(200, {{"total", tx_list.size()}, {"transactions", tx_list}});
}

server::HttpResponse TransactionController::get_transaction(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const {
    std::string tx_id = req.path_params.at("transaction_id");
    auto tx_opt = db_->find_transaction_by_id(tx_id);
    if (!tx_opt.has_value()) {
        return server::HttpResponse::error(404, "Not Found", "Transaction not found: " + tx_id);
    }

    // Ownership authorization check for consumer
    if (auth_ctx.is_consumer()) {
        if (!auth_ctx.associated_account_id.has_value() ||
            (tx_opt->sender_account_id != *auth_ctx.associated_account_id &&
             tx_opt->receiver_account_id != *auth_ctx.associated_account_id)) {
            return server::HttpResponse::error(403, "Forbidden", "Access denied: You do not have permission to view this transaction record");
        }
    }

    json res_json = tx_opt->to_json();
    auto flag_opt = db_->find_flag_by_transaction_id(tx_id);
    if (flag_opt.has_value()) {
        res_json["flag"] = flag_opt->to_json();
    }

    return server::HttpResponse::json(200, res_json);
}

server::HttpResponse TransactionController::execute_transaction(const server::HttpRequest& req, const auth::AuthContext& auth_ctx) const {
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        return server::HttpResponse::error(400, "Bad Request", "Malformed JSON request body");
    }

    double amount = 0.0;
    if (body.contains("amount") && body["amount"].is_number()) {
        amount = body["amount"].get<double>();
    } else {
        return server::HttpResponse::error(400, "Bad Request", "Missing or invalid 'amount' field");
    }

    if (amount <= 0.0) {
        return server::HttpResponse::error(400, "Bad Request", "Transfer amount must be strictly greater than 0.00");
    }

    std::string sender_account_id;
    if (auth_ctx.is_consumer()) {
        if (!auth_ctx.associated_account_id.has_value() || auth_ctx.associated_account_id->empty()) {
            return server::HttpResponse::error(403, "Forbidden", "Consumer profile has no associated bank account");
        }
        sender_account_id = *auth_ctx.associated_account_id;
    } else {
        if (body.contains("sender_account_id") && body["sender_account_id"].is_string()) {
            sender_account_id = body["sender_account_id"].get<std::string>();
        } else {
            return server::HttpResponse::error(400, "Bad Request", "Bank employee transfer requires 'sender_account_id'");
        }
    }

    std::optional<models::Account> receiver_acc_opt;
    if (body.contains("receiver_upi_id") && body["receiver_upi_id"].is_string()) {
        std::string receiver_upi = body["receiver_upi_id"].get<std::string>();
        receiver_acc_opt = db_->find_account_by_upi(receiver_upi);
    } else if (body.contains("receiver_account_id") && body["receiver_account_id"].is_string()) {
        std::string receiver_acc_id = body["receiver_account_id"].get<std::string>();
        receiver_acc_opt = db_->find_account_by_id(receiver_acc_id);
    } else {
        return server::HttpResponse::error(400, "Bad Request", "Missing recipient identifier ('receiver_upi_id' or 'receiver_account_id')");
    }

    if (!receiver_acc_opt.has_value()) {
        return server::HttpResponse::error(404, "Not Found", "Recipient account or UPI ID not found in TrustGraph directory");
    }

    auto sender_acc_opt = db_->find_account_by_id(sender_account_id);
    if (!sender_acc_opt.has_value()) {
        return server::HttpResponse::error(404, "Not Found", "Sender account not found");
    }

    if (sender_acc_opt->account_id == receiver_acc_opt->account_id) {
        return server::HttpResponse::error(400, "Bad Request", "Cannot transfer funds to the same account");
    }

    auto eval = engine::FraudDetectionEngine::evaluate_transaction(*sender_acc_opt, *receiver_acc_opt, amount, *db_);

    std::optional<models::TransactionFlag> flag_opt = std::nullopt;
    if (eval.is_flagged) {
        models::TransactionFlag flag;
        flag.risk_score = eval.risk_score;
        flag.risk_level = eval.risk_level;
        flag.reasons = eval.warning_reasons;
        flag.explanation_title = eval.explanation_title;
        flag.recommended_action = eval.recommended_action;
        flag_opt = flag;
    }

    auto transfer_res = db_->execute_atomic_transfer(
        sender_acc_opt->account_id,
        receiver_acc_opt->account_id,
        amount,
        eval.suggested_status,
        flag_opt
    );

    if (!transfer_res.success) {
        return server::HttpResponse::error(400, "Transfer Failed", transfer_res.error_message);
    }

    json response_json = {
        {"transaction_id", transfer_res.transaction.transaction_id},
        {"sender_account_id", transfer_res.transaction.sender_account_id},
        {"receiver_account_id", transfer_res.transaction.receiver_account_id},
        {"amount", transfer_res.transaction.amount},
        {"status", models::transaction_status_to_string(transfer_res.transaction.status)},
        {"risk_score", eval.risk_score},
        {"risk_level", eval.risk_level},
        {"is_flagged", eval.is_flagged},
        {"timestamp", transfer_res.transaction.timestamp}
    };

    if (transfer_res.flag.has_value()) {
        response_json["flag_id"] = transfer_res.flag->flag_id;
        response_json["explanation_title"] = transfer_res.flag->explanation_title;
        response_json["warning_reasons"] = transfer_res.flag->reasons;
        response_json["recommended_action"] = transfer_res.flag->recommended_action;
    }

    auto res = server::HttpResponse::json(201, response_json);
    res.set_header("X-Simulation-Engine", "Decoupled");
    return res;
}

} // namespace trustgraph::controllers
