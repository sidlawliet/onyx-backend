cmake_minimum_required(VERSION 3.20)
project(TrustGraphEngine VERSION 1.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings and optimization flags
if (MSVC)
    add_compile_options(/W4 /EHsc /O2)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O3)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Core Library Sources
set(CORE_SOURCES
    src/utils/crypto_utils.cpp
    src/auth/password_hasher.cpp
    src/auth/jwt_manager.cpp
    src/auth/rbac_middleware.cpp
    src/db/in_memory_store.cpp
    src/engine/fraud_engine.cpp
    src/engine/graph_engine.cpp
    src/server/router.cpp
    src/server/http_server.cpp
    src/controllers/account_controller.cpp
    src/controllers/transaction_controller.cpp
    src/controllers/complaint_controller.cpp
    src/controllers/auth_controller.cpp
)

add_library(trustgraph_core STATIC ${CORE_SOURCES})

# Platform specific libraries
if (WIN32)
    target_link_libraries(trustgraph_core PUBLIC ws2_32 crypt32 bcrypt)
else()
    target_link_libraries(trustgraph_core PUBLIC pthread)
endif()

# Main Server Executable
add_executable(trustgraph_server src/main.cpp)
target_link_libraries(trustgraph_server PRIVATE trustgraph_core)

# Tests
enable_testing()

add_executable(test_crypto_jwt tests/test_crypto_jwt.cpp)
target_link_libraries(test_crypto_jwt PRIVATE trustgraph_core)
add_test(NAME CryptoJwtTest COMMAND test_crypto_jwt)

add_executable(test_db_store tests/test_db_store.cpp)
target_link_libraries(test_db_store PRIVATE trustgraph_core)
add_test(NAME DbStoreTest COMMAND test_db_store)

add_executable(test_auth_api tests/test_auth_api.cpp)
target_link_libraries(test_auth_api PRIVATE trustgraph_core)
add_test(NAME AuthApiTest COMMAND test_auth_api)

add_executable(test_transactions_ledger tests/test_transactions_ledger.cpp)
target_link_libraries(test_transactions_ledger PRIVATE trustgraph_core)
add_test(NAME TransactionsLedgerTest COMMAND test_transactions_ledger)

add_executable(test_explainability_api tests/test_explainability_api.cpp)
target_link_libraries(test_explainability_api PRIVATE trustgraph_core)
add_test(NAME ExplainabilityApiTest COMMAND test_explainability_api)

add_executable(test_complaints_taint tests/test_complaints_taint.cpp)
target_link_libraries(test_complaints_taint PRIVATE trustgraph_core)
add_test(NAME ComplaintsTaintTest COMMAND test_complaints_taint)

add_executable(test_graph_subgraph tests/test_graph_subgraph.cpp)
target_link_libraries(test_graph_subgraph PRIVATE trustgraph_core)
add_test(NAME GraphSubgraphTest COMMAND test_graph_subgraph)

add_executable(test_database_linking tests/test_database_linking.cpp)
target_link_libraries(test_database_linking PRIVATE trustgraph_core)
add_test(NAME DatabaseLinkingTest COMMAND test_database_linking)

