#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <memory>
#include "db/database_interface.hpp"
#include "utils/json.hpp"

namespace trustgraph::engine {

class GraphEngine {
public:
    explicit GraphEngine(db::DatabasePtr db);

    // Multi-hop BFS neighborhood extraction centered around an account node
    nlohmann::json extract_subgraph(const std::string& root_account_id, int max_depth = 2, size_t max_edges = 100) const;

    // Global network metrics for the bank fraud graph
    nlohmann::json compute_network_metrics() const;

private:
    db::DatabasePtr db_;
};

using GraphEnginePtr = std::shared_ptr<GraphEngine>;

} // namespace trustgraph::engine
