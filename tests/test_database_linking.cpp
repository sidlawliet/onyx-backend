#include <cassert>
#include <iostream>
#include <chrono>
#include "db/in_memory_store.hpp"
#include "engine/graph_engine.hpp"
#include "auth/password_hasher.hpp"

using namespace onyx;

void test_database_linking_and_ingestion() {
    std::cout << "[TEST] Running test_database_linking_and_ingestion..." << std::endl;

    db::InMemoryStore store;

    // Verify initial test fixtures before linking
    assert(store.find_account_by_id("ACC-7A1B8C9D").has_value());
    assert(store.find_user_by_username("siddharth_k").has_value());

    // Link database from "databases" directory
    auto t0 = std::chrono::high_resolution_clock::now();
    bool loaded = store.load_from_database_dir("databases");
    auto t1 = std::chrono::high_resolution_clock::now();
    double load_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    assert(loaded);
    std::cout << "  -> Dataset loaded successfully in " << load_ms << " ms" << std::endl;

    // Check account count: 1,000 from database + 3 original test fixtures = 1003
    auto accounts = store.list_accounts();
    std::cout << "  -> Total accounts in store: " << accounts.size() << std::endl;
    assert(accounts.size() >= 1000);

    // Check transaction count: 32,000 from database + 1 original fixture = 32001
    auto transactions = store.list_transactions();
    std::cout << "  -> Total transactions in store: " << transactions.size() << std::endl;
    assert(transactions.size() >= 32000);

    // Check Ground Truth Scenarios
    auto scenarios = store.list_ground_truth_scenarios();
    std::cout << "  -> Total Ground Truth Scenarios: " << scenarios.size() << std::endl;
    assert(scenarios.size() == 5);

    // Check specific scenario typologies
    bool has_fan_out = false, has_layering = false, has_dispersion = false, has_ato = false;
    for (const auto& sc : scenarios) {
        if (sc.typology == "MULE_FAN_OUT") has_fan_out = true;
        if (sc.typology == "LAYERING_CHAIN") has_layering = true;
        if (sc.typology == "RAPID_DISPERSION") has_dispersion = true;
        if (sc.typology == "ACCOUNT_TAKEOVER") has_ato = true;
    }
    assert(has_fan_out && has_layering && has_dispersion && has_ato);

    // Check Ground Truth Accounts
    auto gt_mule = store.find_ground_truth_account("ACC-10096");
    assert(gt_mule.has_value());
    assert(gt_mule->archetype == "MULE_L1_AGGREGATOR");
    assert(gt_mule->is_fraud == true);

    auto gt_vic = store.find_ground_truth_account("ACC-VIC-B01");
    assert(gt_vic.has_value());
    assert(gt_vic->archetype == "VICTIM");
    assert(gt_vic->is_fraud == true);

    // Check O(1) inverted index performance
    auto t_idx_start = std::chrono::high_resolution_clock::now();
    auto mule_txs = store.find_transactions_by_account("ACC-10096");
    auto t_idx_end = std::chrono::high_resolution_clock::now();
    double lookup_us = std::chrono::duration<double, std::micro>(t_idx_end - t_idx_start).count();

    std::cout << "  -> Inverted index lookup for ACC-10096 returned " << mule_txs.size() 
              << " transactions in " << lookup_us << " us" << std::endl;
    assert(!mule_txs.empty());
    assert(lookup_us < 5000); // Must be fast sub-millisecond query

    // Check user provisioning for an ingested account
    auto acc_sample = store.find_account_by_id("ACC-10096");
    assert(acc_sample.has_value());
    auto user_opt = store.find_user_by_username(acc_sample->upi_id);
    assert(user_opt.has_value());
    assert(user_opt->role == models::UserRole::CONSUMER);
    assert(user_opt->associated_account_id.value_or("") == "ACC-10096");
    assert(auth::PasswordHasher::verify_password("password123", user_opt->password_hash));

    std::cout << "  -> test_database_linking_and_ingestion passed!" << std::endl;
}

void test_graph_engine_with_linked_database() {
    std::cout << "[TEST] Running test_graph_engine_with_linked_database..." << std::endl;

    auto store = std::make_shared<db::InMemoryStore>();
    assert(store->load_from_database_dir("databases"));

    engine::GraphEngine graph_engine(store);

    // 1. Extract subgraph for Scenario A Mule Aggregator (ACC-10096)
    auto subgraph_a = graph_engine.extract_subgraph("ACC-10096", 2, 50);
    assert(!subgraph_a.contains("error"));
    assert(subgraph_a.contains("elements"));
    assert(subgraph_a["elements"].contains("nodes") && subgraph_a["elements"]["nodes"].is_array());
    assert(subgraph_a["elements"].contains("edges") && subgraph_a["elements"]["edges"].is_array());
    std::cout << "  -> Subgraph for ACC-10096 extracted " << subgraph_a["elements"]["nodes"].size() 
              << " nodes and " << subgraph_a["elements"]["edges"].size() << " edges." << std::endl;
    assert(subgraph_a["elements"]["nodes"].size() >= 4); // Root + 3 Mule L2 nodes or victims
    assert(subgraph_a["elements"]["edges"].size() >= 3);

    // 2. Extract subgraph for Scenario B Layering Chain (ACC-VIC-B01)
    auto subgraph_b = graph_engine.extract_subgraph("ACC-VIC-B01", 3, 50);
    assert(!subgraph_b.contains("error"));
    std::cout << "  -> Subgraph for ACC-VIC-B01 extracted " << subgraph_b["elements"]["nodes"].size() 
              << " nodes and " << subgraph_b["elements"]["edges"].size() << " edges." << std::endl;
    assert(subgraph_b["elements"]["nodes"].size() >= 2);

    // 3. Compute Network Metrics across the full 1,000-node graph
    auto metrics = graph_engine.compute_network_metrics();
    assert(metrics.contains("total_nodes"));
    assert(metrics.contains("total_transactions"));
    assert(metrics["total_nodes"].get<size_t>() >= 1000);
    assert(metrics["total_transactions"].get<size_t>() >= 32000);
    std::cout << "  -> Global Network Metrics: " << metrics["total_nodes"] << " nodes, " 
              << metrics["total_transactions"] << " transactions." << std::endl;

    std::cout << "  -> test_graph_engine_with_linked_database passed!" << std::endl;
}

int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << "   RUNNING DATABASE LINKING TESTS         " << std::endl;
    std::cout << "==========================================" << std::endl;

    test_database_linking_and_ingestion();
    test_graph_engine_with_linked_database();

    std::cout << "All Database Linking tests passed successfully!" << std::endl;
    return 0;
}
