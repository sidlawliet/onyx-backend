#include "engine/graph_engine.hpp"
#include <queue>
#include <algorithm>

namespace trustgraph::engine {

GraphEngine::GraphEngine(db::DatabasePtr db) : db_(std::move(db)) {}

nlohmann::json GraphEngine::extract_subgraph(const std::string& root_account_id, int max_depth, size_t max_edges) const {
    if (max_depth < 1) max_depth = 1;
    if (max_depth > 5) max_depth = 5;
    max_edges = std::clamp(max_edges, static_cast<size_t>(1), static_cast<size_t>(500));

    // 1. Resolve root account
    std::string root_id = root_account_id;
    auto root_acc = db_->find_account_by_id(root_id);
    if (!root_acc.has_value()) {
        auto upi_acc = db_->find_account_by_upi(root_id);
        if (upi_acc.has_value()) {
            root_id = upi_acc->account_id;
            root_acc = upi_acc;
        } else {
            return {
                {"error", "Not Found"},
                {"message", "Root account not found: " + root_account_id}
            };
        }
    }

    nlohmann::json nodes_json = nlohmann::json::array();
    nlohmann::json edges_json = nlohmann::json::array();

    std::unordered_set<std::string> visited_nodes;
    std::unordered_set<std::string> collected_edges;
    std::queue<std::pair<std::string, int>> bfs_queue;

    bfs_queue.push({root_id, 0});
    visited_nodes.insert(root_id);

    while (!bfs_queue.empty()) {
        auto [curr_id, curr_depth] = bfs_queue.front();
        bfs_queue.pop();

        auto acc_opt = db_->find_account_by_id(curr_id);
        if (acc_opt.has_value()) {
            const auto& acc = *acc_opt;
            size_t complaints = db_->count_complaints_for_suspect(acc.account_id);

            std::string risk_level = "LOW";
            if (acc.status == models::AccountStatus::FROZEN || acc.status == models::AccountStatus::FLAGGED || acc.risk_score >= 70.0) {
                risk_level = "CRITICAL";
            } else if (acc.risk_score >= 40.0) {
                risk_level = "HIGH";
            } else if (acc.risk_score >= 20.0) {
                risk_level = "MEDIUM";
            }

            std::string node_type = acc.is_verified_merchant ? "MERCHANT" : acc.account_type;
            auto gt_opt = db_->find_ground_truth_account(acc.account_id);
            if (gt_opt.has_value() && !gt_opt->archetype.empty()) {
                node_type = gt_opt->archetype;
            }

            double score = acc.risk_score;
            if (score > 0.0 && score <= 1.0) {
                score *= 100.0;
            }
            score = std::min(100.0, std::max(0.0, score));

            nodes_json.push_back({
                {"data", {
                    {"id", acc.account_id},
                    {"label", acc.upi_id},
                    {"type", node_type},
                    {"account_type", acc.account_type},
                    {"holder_name", acc.holder_name},
                    {"status", models::account_status_to_string(acc.status)},
                    {"risk_score", score},
                    {"risk_level", risk_level},
                    {"is_root", (acc.account_id == root_id)},
                    {"is_frozen", (acc.status == models::AccountStatus::FROZEN)},
                    {"complaint_count", complaints}
                }}
            });
        }

        if (curr_depth < max_depth && edges_json.size() < max_edges) {
            auto txs = db_->find_transactions_by_account(curr_id);
            for (const auto& tx : txs) {
                if (edges_json.size() >= max_edges) {
                    break;
                }

                if (collected_edges.find(tx.transaction_id) == collected_edges.end()) {
                    collected_edges.insert(tx.transaction_id);

                    auto flag_opt = db_->find_flag_by_transaction_id(tx.transaction_id);
                    edges_json.push_back({
                        {"data", {
                            {"id", tx.transaction_id},
                            {"source", tx.sender_account_id},
                            {"target", tx.receiver_account_id},
                            {"amount", tx.amount},
                            {"status", models::transaction_status_to_string(tx.status)},
                            {"is_flagged", flag_opt.has_value()},
                            {"timestamp", tx.timestamp}
                        }}
                    });

                    // Check neighbors
                    std::string neighbor_id = (tx.sender_account_id == curr_id) ? tx.receiver_account_id : tx.sender_account_id;
                    if (visited_nodes.find(neighbor_id) == visited_nodes.end()) {
                        visited_nodes.insert(neighbor_id);
                        bfs_queue.push({neighbor_id, curr_depth + 1});
                    }
                }
            }
        }
    }

    return {
        {"root_account_id", root_id},
        {"depth", max_depth},
        {"node_count", nodes_json.size()},
        {"edge_count", edges_json.size()},
        {"elements", {
            {"nodes", nodes_json},
            {"edges", edges_json}
        }}
    };
}

nlohmann::json GraphEngine::compute_network_metrics() const {
    auto accounts = db_->list_accounts();
    auto transactions = db_->list_transactions();

    size_t active_nodes = 0;
    size_t flagged_nodes = 0;
    size_t frozen_nodes = 0;

    for (const auto& acc : accounts) {
        if (acc.status == models::AccountStatus::ACTIVE) active_nodes++;
        else if (acc.status == models::AccountStatus::FLAGGED) flagged_nodes++;
        else if (acc.status == models::AccountStatus::FROZEN) frozen_nodes++;
    }

    size_t flagged_tx_count = 0;
    double total_held_volume = 0.0;
    double total_volume = 0.0;

    for (const auto& tx : transactions) {
        total_volume += tx.amount;
        if (tx.status == models::TransactionStatus::HELD) {
            total_held_volume += tx.amount;
        }
        auto flag_opt = db_->find_flag_by_transaction_id(tx.transaction_id);
        if (flag_opt.has_value()) {
            flagged_tx_count++;
        }
    }

    return {
        {"total_nodes", accounts.size()},
        {"active_nodes", active_nodes},
        {"flagged_nodes", flagged_nodes},
        {"frozen_nodes", frozen_nodes},
        {"total_transactions", transactions.size()},
        {"flagged_transactions", flagged_tx_count},
        {"total_held_volume", total_held_volume},
        {"total_transaction_volume", total_volume}
    };
}

} // namespace trustgraph::engine
