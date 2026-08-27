#include <cassert>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include "db/in_memory_store.hpp"
#include "engine/fraud_engine.hpp"

using namespace onyx;

void test_normal_atomic_transfer() {
    std::cout << "[TEST] Running test_normal_atomic_transfer..." << std::endl;

    db::InMemoryStore store;

    // Create a benign clean receiver account
    models::Account clean_receiver;
    clean_receiver.account_id = "ACC-CLEAN-01";
    clean_receiver.upi_id = "merchant_clean@upi";
    clean_receiver.holder_name = "Clean Merchant Services";
    clean_receiver.balance = 10000.00;
    clean_receiver.risk_score = 4.0;
    clean_receiver.status = models::AccountStatus::ACTIVE;
    store.create_account(clean_receiver);

    auto sender_before = store.find_account_by_id("ACC-7A1B8C9D");
    assert(sender_before.has_value());
    double sender_initial_balance = sender_before->balance;

    // Evaluate heuristics
    auto eval = engine::FraudDetectionEngine::evaluate_transaction(*sender_before, clean_receiver, 2000.00, store);
    assert(eval.is_flagged == false);
    assert(eval.suggested_status == models::TransactionStatus::COMPLETED);
    assert(eval.risk_level == "LOW");

    // Execute transfer
    auto res = store.execute_atomic_transfer(sender_before->account_id, clean_receiver.account_id, 2000.00, eval.suggested_status);
    assert(res.success == true);
    assert(res.transaction.status == models::TransactionStatus::COMPLETED);
    assert(res.transaction.amount == 2000.00);

    // Verify balances
    auto sender_after = store.find_account_by_id("ACC-7A1B8C9D");
    auto receiver_after = store.find_account_by_id("ACC-CLEAN-01");
    assert(sender_after->balance == sender_initial_balance - 2000.00);
    assert(receiver_after->balance == 10000.00 + 2000.00);

    std::cout << "  -> test_normal_atomic_transfer passed!" << std::endl;
}

void test_insufficient_funds_and_validation() {
    std::cout << "[TEST] Running test_insufficient_funds_and_validation..." << std::endl;

    db::InMemoryStore store;
    auto sender = store.find_account_by_id("ACC-7A1B8C9D");
    auto receiver = store.find_account_by_upi("invest_guru@ybl");

    // Amount exceeds balance
    auto res_overdraw = store.execute_atomic_transfer(sender->account_id, receiver->account_id, sender->balance + 50000.00, models::TransactionStatus::COMPLETED);
    assert(res_overdraw.success == false);
    assert(!res_overdraw.error_message.empty());

    // Non-positive amount
    auto res_zero = store.execute_atomic_transfer(sender->account_id, receiver->account_id, 0.00, models::TransactionStatus::COMPLETED);
    assert(res_zero.success == false);

    // Negative amount
    auto res_neg = store.execute_atomic_transfer(sender->account_id, receiver->account_id, -500.00, models::TransactionStatus::COMPLETED);
    assert(res_neg.success == false);

    // Non-existent receiver
    auto res_no_rec = store.execute_atomic_transfer(sender->account_id, "ACC-DOESNT-EXIST", 100.00, models::TransactionStatus::COMPLETED);
    assert(res_no_rec.success == false);

    std::cout << "  -> test_insufficient_funds_and_validation passed!" << std::endl;
}

void test_frozen_account_guard() {
    std::cout << "[TEST] Running test_frozen_account_guard..." << std::endl;

    db::InMemoryStore store;

    // Create a frozen sender account
    models::Account frozen_acc;
    frozen_acc.account_id = "ACC-FROZEN-01";
    frozen_acc.upi_id = "frozen_user@upi";
    frozen_acc.holder_name = "Frozen Node";
    frozen_acc.balance = 50000.00;
    frozen_acc.status = models::AccountStatus::FROZEN;
    store.create_account(frozen_acc);

    auto receiver = store.find_account_by_id("ACC-7A1B8C9D");

    // Outbound from frozen account
    auto res_out = store.execute_atomic_transfer(frozen_acc.account_id, receiver->account_id, 1000.00, models::TransactionStatus::COMPLETED);
    assert(res_out.success == false);
    assert(res_out.error_message.find("FROZEN") != std::string::npos);

    // Inbound to frozen account
    auto res_in = store.execute_atomic_transfer(receiver->account_id, frozen_acc.account_id, 1000.00, models::TransactionStatus::COMPLETED);
    assert(res_in.success == false);
    assert(res_in.error_message.find("FROZEN") != std::string::npos);

    std::cout << "  -> test_frozen_account_guard passed!" << std::endl;
}

void test_suspicious_mule_flagging_and_held_state() {
    std::cout << "[TEST] Running test_suspicious_mule_flagging_and_held_state..." << std::endl;

    db::InMemoryStore store;
    auto sender = store.find_account_by_id("ACC-7A1B8C9D");
    auto suspect_receiver = store.find_account_by_upi("invest_guru@ybl"); // Risk 88.5, FLAGGED

    assert(sender.has_value() && suspect_receiver.has_value());
    double sender_balance_before = sender->balance;
    double receiver_balance_before = suspect_receiver->balance;

    // Run Fraud Engine
    auto eval = engine::FraudDetectionEngine::evaluate_transaction(*sender, *suspect_receiver, 45000.00, store);
    assert(eval.is_flagged == true);
    assert(eval.risk_level == "CRITICAL");
    assert(eval.suggested_status == models::TransactionStatus::HELD);
    assert(eval.explanation_title == "High Velocity Mule Pass-Through Detected");
    assert(eval.warning_reasons.size() >= 2);

    // Create flag record
    models::TransactionFlag flag;
    flag.risk_score = eval.risk_score;
    flag.risk_level = eval.risk_level;
    flag.reasons = eval.warning_reasons;
    flag.explanation_title = eval.explanation_title;
    flag.recommended_action = eval.recommended_action;

    // Execute atomic transfer with HELD status
    auto res = store.execute_atomic_transfer(sender->account_id, suspect_receiver->account_id, 45000.00, eval.suggested_status, flag);
    assert(res.success == true);
    assert(res.transaction.status == models::TransactionStatus::HELD);
    assert(res.flag.has_value());
    assert(res.flag->risk_level == "CRITICAL");

    // Funds held: Sender is debited, but receiver is NOT yet credited
    auto sender_after = store.find_account_by_id(sender->account_id);
    auto receiver_after = store.find_account_by_id(suspect_receiver->account_id);
    assert(sender_after->balance == sender_balance_before - 45000.00);
    assert(receiver_after->balance == receiver_balance_before); // Not credited

    // Check flag persistence
    auto persisted_flag = store.find_flag_by_transaction_id(res.transaction.transaction_id);
    assert(persisted_flag.has_value());
    assert(persisted_flag->explanation_title == "High Velocity Mule Pass-Through Detected");

    std::cout << "  -> test_suspicious_mule_flagging_and_held_state passed!" << std::endl;
}

void test_concurrent_transfers_no_overdraw() {
    std::cout << "[TEST] Running test_concurrent_transfers_no_overdraw..." << std::endl;

    db::InMemoryStore store;

    // Account with exact 1000.00 balance
    models::Account sender;
    sender.account_id = "ACC-RACE-01";
    sender.upi_id = "race_sender@bank";
    sender.holder_name = "Race Test Sender";
    sender.balance = 1000.00;
    sender.status = models::AccountStatus::ACTIVE;
    store.create_account(sender);

    models::Account receiver;
    receiver.account_id = "ACC-RACE-REC";
    receiver.upi_id = "race_receiver@bank";
    receiver.holder_name = "Race Test Receiver";
    receiver.balance = 0.00;
    receiver.status = models::AccountStatus::ACTIVE;
    store.create_account(receiver);

    const int num_threads = 10;
    const double transfer_amount = 200.00;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    std::atomic<int> fail_count{0};

    // 10 threads each try to transfer 200.00 simultaneously from a 1000.00 account
    // Exactly 5 must succeed (5 * 200 = 1000), 5 must fail with insufficient funds
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&store, &success_count, &fail_count, transfer_amount]() {
            auto res = store.execute_atomic_transfer("ACC-RACE-01", "ACC-RACE-REC", transfer_amount, models::TransactionStatus::COMPLETED);
            if (res.success) {
                success_count++;
            } else {
                fail_count++;
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    assert(success_count.load() == 5);
    assert(fail_count.load() == 5);

    auto final_sender = store.find_account_by_id("ACC-RACE-01");
    auto final_receiver = store.find_account_by_id("ACC-RACE-REC");
    assert(final_sender->balance == 0.00);
    assert(final_receiver->balance == 1000.00);

    std::cout << "  -> test_concurrent_transfers_no_overdraw passed! (Success: " << success_count.load() << ", Rejections: " << fail_count.load() << ")" << std::endl;
}

int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << "   RUNNING TRANSACTIONS LEDGER TESTS      " << std::endl;
    std::cout << "==========================================" << std::endl;

    test_normal_atomic_transfer();
    test_insufficient_funds_and_validation();
    test_frozen_account_guard();
    test_suspicious_mule_flagging_and_held_state();
    test_concurrent_transfers_no_overdraw();

    std::cout << "All Transaction Ledger & Flag tests passed successfully!" << std::endl;
    return 0;
}
