#pragma once

#include <string>
#include "utils/json.hpp"

namespace trustgraph::models {

struct GroundTruthAccount {
    std::string account_id;
    std::string archetype;
    bool is_fraud = false;

    nlohmann::json to_json() const {
        return {
            {"account_id", account_id},
            {"archetype", archetype},
            {"is_fraud", is_fraud}
        };
    }
};

struct GroundTruthScenario {
    std::string scenario_id;
    std::string typology;
    std::string root_source_id;
    double total_stolen_amount = 0.0;
    std::string start_time;
    std::string end_time;

    nlohmann::json to_json() const {
        return {
            {"scenario_id", scenario_id},
            {"typology", typology},
            {"root_source_id", root_source_id},
            {"total_stolen_amount", total_stolen_amount},
            {"start_time", start_time},
            {"end_time", end_time}
        };
    }
};

} // namespace trustgraph::models
