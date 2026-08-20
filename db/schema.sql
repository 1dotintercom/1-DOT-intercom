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
    owner_admin_id UUID REFERENCES users(id) ON DELETE SET NULL,
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

-- 5. Device-bound software licenses
CREATE TABLE IF NOT EXISTS licenses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    license_key VARCHAR(64) UNIQUE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'unused' CHECK (status IN ('unused', 'active', 'revoked')),
    device_fingerprint VARCHAR(128),
    activated_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    issued_to VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS license_verification_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    license_key VARCHAR(64) NOT NULL,
    device_fingerprint VARCHAR(128),
    result VARCHAR(32) NOT NULL,
    ip_address INET,
    details JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);
CREATE INDEX IF NOT EXISTS idx_license_logs_key ON license_verification_log(license_key, created_at DESC);

-- Licensed administrator accounts are linked to exactly one license. The
-- global bootstrap administrator remains unlinked and manages license issuance.
ALTER TABLE users ADD COLUMN IF NOT EXISTS license_id UUID REFERENCES licenses(id) ON DELETE SET NULL;
ALTER TABLE panels ADD COLUMN IF NOT EXISTS owner_admin_id UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_license_id ON users(license_id) WHERE license_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_panels_owner_admin ON panels(owner_admin_id);

-- Panel codes belong to an administrator's matrix, not to the whole system.
-- Remove the original global constraint so a fresh license can reuse codes
-- from an expired/revoked administrator without sharing any account.
ALTER TABLE panels DROP CONSTRAINT IF EXISTS panels_panel_code_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_panels_owner_code ON panels(owner_admin_id, panel_code);
