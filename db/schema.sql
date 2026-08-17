-- Mobile IC Agent Database Schema
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Users table (authentication & roles)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'panel_user')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Panels table (panel accounts, locations & online status)
CREATE TABLE IF NOT EXISTS panels (
    id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    panel_code VARCHAR(20) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    location VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'offline' CHECK (status IN ('online', 'offline')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Permissions table (N x N pair matrix state)
CREATE TABLE IF NOT EXISTS permissions (
    panel_a_id UUID NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    panel_b_id UUID NOT NULL REFERENCES panels(id) ON DELETE CASCADE,
    state VARCHAR(50) NOT NULL CHECK (state IN ('blocked', 'listen', 'talk', 'both')),
    updated_by_admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (panel_a_id, panel_b_id)
);

-- 4. Audit Logs table (Immutable event log)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL CHECK (event_type IN ('permission_change', 'session_start', 'session_end', 'system_event')),
    admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
    panel_from UUID REFERENCES panels(id) ON DELETE SET NULL,
    panel_to UUID REFERENCES panels(id) ON DELETE SET NULL,
    old_state VARCHAR(50),
    new_state VARCHAR(50),
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indices for rapid querying & filterable audit logs
CREATE INDEX IF NOT EXISTS idx_permissions_panel_a ON permissions(panel_a_id);
CREATE INDEX IF NOT EXISTS idx_permissions_panel_b ON permissions(panel_b_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_panels ON audit_logs(panel_from, panel_to);
