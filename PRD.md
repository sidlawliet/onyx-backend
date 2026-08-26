# Product Requirements Document (PRD): TrustGraph C++ Backend Engine (v1.2)

---

## 1. Executive Summary & Objective

**TrustGraph** is a real-time financial fraud intelligence engine designed to detect, analyze, and trace multi-hop fraud networks.

This update (v1.2) introduces:
- **Role-Based Authentication (RBAC):** Dual login flows (`CONSUMER` vs. `BANK_EMPLOYEE`) using JWT-based session security.
- **Explainable Flagging for Consumers:** Auditable, human-readable reason payloads explaining why an outbound transaction or recipient was flagged.
- **Fraud Complaint & Dispute Pipeline:** Consumer-facing fraud reporting mechanism that persists directly into the bank's internal complaints registry, triggering automatic graph taint updates.

---

## 2. Technical Architecture & RBAC Flow

```
               ┌────────────────────────────────────────────────────────┐
               │         Frontend Layer (React / Next.js / Tailwind)     │
               └───────────────────┬────────────────────────────────────┘
                                   │
                    HTTP Requests (Bearer JWT Header)
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│                        TrustGraph C++ Backend                         │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Auth & RBAC Middleware (JWT Validation + Role Checks)           │  │
│  └──────────────────┬───────────────────────────────┬──────────────┘  │
│                     │                               │                 │
│      [ Role: CONSUMER ]                   [ Role: BANK_EMPLOYEE ]     │
│  ┌──────────────────────────────┐    ┌─────────────────────────────┐  │
│  │ - Check Recipient Risk       │    │ - Full Graph Investigation  │  │
│  │ - View My Account & History  │    │ - Flag/Freeze Node Actions  │  │
│  │ - File Fraud Complaint       │    │ - Manage Complaints Triage  │  │
│  │ - View Flag Explanations     │    │ - Global Alert Dashboard    │  │
│  └──────────────┬───────────────┘    └──────────────┬──────────────┘  │
│                 │                                   │                 │
│                 └─────────────────┬─────────────────┘                 │
│                                   ▼                                   │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Core Analytics, Graph Engine & Postgres DB Access Layer         │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 3. Database Schema Extensions

### 3.1 Users & Authentication (`users`)

```sql
CREATE TABLE users (
    user_id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL, -- 'CONSUMER', 'BANK_EMPLOYEE'
    associated_account_id VARCHAR(32) REFERENCES accounts(account_id), -- NULL for bank employees
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
```

### 3.2 Flagged Transaction Reasons (`transaction_flags`)

Stores the exact heuristic signals triggered when a transaction is flagged.

```sql
CREATE TABLE transaction_flags (
    flag_id VARCHAR(36) PRIMARY KEY,
    transaction_id VARCHAR(36) REFERENCES transactions(transaction_id),
    risk_score NUMERIC(5, 2) NOT NULL,
    risk_level VARCHAR(15) NOT NULL, -- 'MEDIUM', 'HIGH', 'CRITICAL'
    reasons JSONB NOT NULL,          -- Array of strings explaining the flag
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_flags_tx ON transaction_flags(transaction_id);
```

### 3.3 Fraud Complaints Registry (`fraud_complaints`)

```sql
CREATE TABLE fraud_complaints (
    complaint_id VARCHAR(36) PRIMARY KEY,
    complainant_account_id VARCHAR(32) REFERENCES accounts(account_id) NOT NULL,
    suspect_account_id VARCHAR(32) REFERENCES accounts(account_id) NOT NULL,
    transaction_id VARCHAR(36) REFERENCES transactions(transaction_id),
    amount NUMERIC(14, 2) NOT NULL,
    scam_category VARCHAR(50) NOT NULL, -- 'TASK_JOB_SCAM', 'INVESTMENT_FRAUD', 'PHISHING', 'MULE_SUSPECT'
    description TEXT,
    status VARCHAR(20) DEFAULT 'SUBMITTED', -- 'SUBMITTED', 'UNDER_INVESTIGATION', 'RESOLVED', 'REJECTED'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_complaints_suspect ON fraud_complaints(suspect_account_id);
CREATE INDEX idx_complaints_status ON fraud_complaints(status);
```

---

## 4. REST API Specification Updates

### 4.1 Authentication & Role-Based Login

- **Endpoint:** `POST /api/v1/auth/login`
- **Access:** Public

#### Request Body
```json
{
  "username": "siddharth_k",
  "password": "secure_password_123",
  "role": "CONSUMER"
}
```
*(Note: `role` can be `"CONSUMER"` or `"BANK_EMPLOYEE"`).*

#### Response (`200 OK`)
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "user": {
    "user_id": "USR-8819A",
    "username": "siddharth_k",
    "role": "CONSUMER",
    "associated_account_id": "ACC-7A1B8C9D"
  }
}
```

---

### 4.2 Explainable Flagging & Transaction Inspection

- **Endpoint:** `GET /api/v1/transactions/{transaction_id}/flag-details`
- **Access:** `CONSUMER` (associated with transaction) or `BANK_EMPLOYEE`

#### Response (`200 OK`)
```json
{
  "transaction_id": "TXN-88F19280AA",
  "amount": 45000.00,
  "timestamp": "2026-08-25T14:35:12Z",
  "status": "HELD",
  "risk_score": 88.5,
  "risk_level": "CRITICAL",
  "explanation_title": "High Velocity Mule Pass-Through Detected",
  "warning_reasons": [
    "Recipient account created less than 4 days ago.",
    "Abnormal Inflow: Recipient received deposits from 9 distinct UPI accounts in the last 30 minutes.",
    "Rapid Drain Velocity: 94% of accumulated funds were transferred onward within 8 minutes of arrival."
  ],
  "recommended_action": "Do not approve or send additional funds. Report this transaction if unsolicited."
}
```

---

### 4.3 Fraud Complaint Management

#### 4.3.1 Submit Complaint
- **Endpoint:** `POST /api/v1/complaints`
- **Access:** `CONSUMER`

##### Request Body
```json
{
  "transaction_id": "TXN-88F19280AA",
  "suspect_upi_id": "invest_guru@ybl",
  "scam_category": "TASK_JOB_SCAM",
  "description": "Was promised daily returns for rating videos on Telegram; receiver demanded continuous deposits."
}
```

##### Processing Rules
1. Verify complainant ownership of `transaction_id`.
2. Resolve `suspect_upi_id` to `suspect_account_id`.
3. Insert complaint record into `fraud_complaints`.
4. Automatically increment `risk_score` (+25.0) and set `status = 'FLAGGED'` on the suspect account if active complaints $\ge 2$.

##### Response (`201 Created`)
```json
{
  "complaint_id": "CMP-2026-0091",
  "status": "SUBMITTED",
  "message": "Complaint logged in Bank Fraud Registry. Taint score updated on recipient node.",
  "timestamp": "2026-08-25T14:40:00Z"
}
```

---

#### 4.3.2 Query / Triage Complaints
- **Endpoint:** `GET /api/v1/complaints`
- **Access:** `BANK_EMPLOYEE` only
- **Query Parameters:** `?status=SUBMITTED&limit=50`

##### Response (`200 OK`)
```json
{
  "total": 1,
  "complaints": [
    {
      "complaint_id": "CMP-2026-0091",
      "complainant_account_id": "ACC-7A1B8C9D",
      "suspect_account_id": "ACC-9F2E4A10",
      "amount": 45000.00,
      "scam_category": "TASK_JOB_SCAM",
      "status": "SUBMITTED",
      "created_at": "2026-08-25T14:40:00Z"
    }
  ]
}
```

---

## 5. Implementation Roadmap

| Milestone | Deliverable | Scope / Features |
| :--- | :--- | :--- |
| **M1: Database & Auth Core** | C++ JWT Auth + RBAC | • `users`, `accounts`, `transactions` schema setup.<br>• Argon2/Bcrypt password hashing in C++.<br>• Dual role token issuing (`CONSUMER` vs. `BANK_EMPLOYEE`).<br>• Auth middleware for route protection. |
| **M2: Atomic Ledger & Flags** | Transaction Pipeline | • `POST /api/v1/transactions` with `SELECT FOR UPDATE`.<br>• Real-time trigger generating `transaction_flags` records on suspicious transfers. |
| **M3: Consumer Safety & Flag Explanations** | Explainability APIs | • `GET /api/v1/accounts/verify-risk/{upi_id}`.<br>• `GET /api/v1/transactions/{id}/flag-details` with human-readable reasoning strings. |
| **M4: Complaints & Taint Engine** | Fraud Registry | • `POST /api/v1/complaints` ingestion.<br>• Feedback loop: auto-tainting suspect node and updating graph risk score upon complaint filing.<br>• `GET /api/v1/complaints` triage endpoint for Bank Employees. |
| **M5: Graph Subgraph Extraction** | Visualization Support | • `GET /api/v1/graph/subgraph/{id}` exporting nodes/edges JSON for React/Cytoscape frontend rendering. |
