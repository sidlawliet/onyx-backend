-- ONYX Financial Fraud Intelligence Engine
-- PostgreSQL Database Initialization Schema (v1.2)

-- Ensure UUID extension is available if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Accounts Table
CREATE TABLE IF NOT EXISTS accounts (
    account_id VARCHAR(32) PRIMARY KEY,
    upi_id VARCHAR(100) UNIQUE NOT NULL,
    holder_name VARCHAR(100) NOT NULL,
    balance NUMERIC(14, 2) NOT NULL DEFAULT 0.00 CHECK (balance >= 0.00),
    risk_score NUMERIC(5, 2) NOT NULL DEFAULT 0.00,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'FLAGGED', 'FROZEN'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_accounts_upi ON accounts(upi_id);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_accounts_risk ON accounts(risk_score);

-- 2. Users Table (Authentication & RBAC)
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('CONSUMER', 'BANK_EMPLOYEE')),
    associated_account_id VARCHAR(32) REFERENCES accounts(account_id) ON DELETE SET NULL, -- NULL for bank employees
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_account ON users(associated_account_id);

-- 3. Transactions Table (Multi-hop ledger)
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id VARCHAR(36) PRIMARY KEY,
    sender_account_id VARCHAR(32) REFERENCES accounts(account_id) NOT NULL,
    receiver_account_id VARCHAR(32) REFERENCES accounts(account_id) NOT NULL,
    amount NUMERIC(14, 2) NOT NULL CHECK (amount > 0.00),
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'COMPLETED', 'HELD', 'FLAGGED', 'REJECTED'
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_transactions_sender ON transactions(sender_account_id);
CREATE INDEX IF NOT EXISTS idx_transactions_receiver ON transactions(receiver_account_id);
CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);

-- 4. Flagged Transaction Reasons (Explainability Engine)
CREATE TABLE IF NOT EXISTS transaction_flags (
    flag_id VARCHAR(36) PRIMARY KEY,
    transaction_id VARCHAR(36) REFERENCES transactions(transaction_id) ON DELETE CASCADE,
    risk_score NUMERIC(5, 2) NOT NULL,
    risk_level VARCHAR(15) NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    reasons JSONB NOT NULL,          -- Array of strings explaining the flag
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_flags_tx ON transaction_flags(transaction_id);
CREATE INDEX IF NOT EXISTS idx_flags_risk_level ON transaction_flags(risk_level);

-- 5. Fraud Complaints Registry (Consumer reporting & Taint feedback)
CREATE TABLE IF NOT EXISTS fraud_complaints (
    complaint_id VARCHAR(36) PRIMARY KEY,
    complainant_account_id VARCHAR(32) REFERENCES accounts(account_id) NOT NULL,
    suspect_account_id VARCHAR(32) REFERENCES accounts(account_id) NOT NULL,
    transaction_id VARCHAR(36) REFERENCES transactions(transaction_id) ON DELETE SET NULL,
    amount NUMERIC(14, 2) NOT NULL CHECK (amount > 0.00),
    scam_category VARCHAR(50) NOT NULL CHECK (scam_category IN ('TASK_JOB_SCAM', 'INVESTMENT_FRAUD', 'PHISHING', 'MULE_SUSPECT', 'OTHER')),
    description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'SUBMITTED' CHECK (status IN ('SUBMITTED', 'UNDER_INVESTIGATION', 'RESOLVED', 'REJECTED')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_complaints_suspect ON fraud_complaints(suspect_account_id);
CREATE INDEX IF NOT EXISTS idx_complaints_complainant ON fraud_complaints(complainant_account_id);
CREATE INDEX IF NOT EXISTS idx_complaints_status ON fraud_complaints(status);
CREATE INDEX IF NOT EXISTS idx_complaints_created_at ON fraud_complaints(created_at);
