#include <cassert>
#include <iostream>
#include <thread>
#include <vector>
#include "db/in_memory_store.hpp"

using namespace trustgraph;

void test_db_seeding_and_lookups() {
    std::cout << "[TEST] Running test_db_seeding_and_lookups..." << std::endl;

    db::InMemoryStore store;

    // Check seeded user
    auto user_opt = store.find_user_by_username("siddharth_k");
    assert(user_opt.has_value());
    assert(user_opt->user_id == "USR-8819A");
    assert(user_opt->role == models::UserRole::CONSUMER);
    assert(user_opt->associated_account_id.value_or("") == "ACC-7A1B8C9D");

    // Check bank employee
    auto emp_opt = store.find_user_by_username("analyst_raj");
    assert(emp_opt.has_value());
    assert(emp_opt->role == models::UserRole::BANK_EMPLOYEE);
    assert(!emp_opt->associated_account_id.has_value());

    // Check account lookup
    auto acc_opt = store.find_account_by_upi("invest_guru@ybl");
    assert(acc_opt.has_value());
    assert(acc_opt->account_id == "ACC-9F2E4A10");
    assert(acc_opt->status == models::AccountStatus::FLAGGED);

    // Check transaction and flag lookup
    auto tx_opt = store.find_transaction_by_id("TXN-88F19280AA");
    assert(tx_opt.has_value());
    assert(tx_opt->amount == 45000.00);

    auto flag_opt = store.find_flag_by_transaction_id("TXN-88F19280AA");
    assert(flag_opt.has_value());
    assert(flag_opt->risk_level == "CRITICAL");
    assert(flag_opt->risk_score == 88.5);
    assert(flag_opt->reasons.size() == 3);

    std::cout << "  -> test_db_seeding_and_lookups passed!" << std::endl;
}

void test_db_concurrency() {
    std::cout << "[TEST] Running test_db_concurrency..." << std::endl;

    db::InMemoryStore store;
    const int num_threads = 8;
    const int ops_per_thread = 100;
    std::vector<std::thread> threads;

    // Concurrent writers creating accounts and users
    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&store, t, ops_per_thread]() {
            for (int i = 0; i < ops_per_thread; ++i) {
                std::string acc_id = "ACC-T" + std::to_string(t) + "-" + std::to_string(i);
                std::string upi = "user_" + std::to_string(t) + "_" + std::to_string(i) + "@bank";

                models::Account acc;
                acc.account_id = acc_id;
                acc.upi_id = upi;
                acc.holder_name = "User " + std::to_string(t);
                acc.balance = 1000.0 + i;
                acc.status = models::AccountStatus::ACTIVE;
                store.create_account(acc);

                // Concurrent reads
                auto read_acc = store.find_account_by_upi(upi);
                assert(read_acc.has_value());
                assert(read_acc->account_id == acc_id);
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    auto all_accounts = store.list_accounts();
    // 3 seeded + 800 new
    assert(all_accounts.size() == 3 + (num_threads * ops_per_thread));

    std::cout << "  -> test_db_concurrency passed!" << std::endl;
}

int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << "   RUNNING IN-MEMORY DB STORE TESTS       " << std::endl;
    std::cout << "==========================================" << std::endl;

    test_db_seeding_and_lookups();
    test_db_concurrency();

    std::cout << "All Database Store tests passed successfully!" << std::endl;
    return 0;
}
