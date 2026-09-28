-- =============================================================================
-- AegisX SOC Platform — PostgreSQL 16+ Database Schema
-- =============================================================================
--
-- This schema implements the full AegisX database model as specified in the
-- architecture contracts. It covers the complete SOC pipeline from endpoint
-- registration through telemetry, detection, correlation, AI triage,
-- investigation, response, and audit.
--
-- Requirements: PostgreSQL 16+ with pgvector extension.
--
-- Usage:
--   CREATE DATABASE aegisx;
--   \c aegisx
--   CREATE EXTENSION IF NOT EXISTS vector;
--   \i schema.sql
-- =============================================================================

-- Enable extensions
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pgvector extension unavailable; vector embeddings will be optional.';
END
$$;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- Custom ENUMs
-- =============================================================================

CREATE TYPE alert_severity AS ENUM (
    'informational', 'low', 'medium', 'high', 'critical'
);

CREATE TYPE alert_status AS ENUM (
    'new', 'triaged', 'investigating', 'resolved', 'false_positive', 'suppressed'
);

CREATE TYPE incident_severity AS ENUM (
    'low', 'medium', 'high', 'critical'
);

CREATE TYPE incident_status AS ENUM (
    'new', 'triaging', 'investigating', 'containment',
    'eradication', 'recovery', 'resolved', 'closed'
);

CREATE TYPE classification_type AS ENUM (
    'benign', 'suspicious', 'likely_malicious',
    'confirmed_malicious', 'insufficient_evidence'
);

CREATE TYPE detection_type AS ENUM (
    'rule', 'ioc', 'behavioral', 'anomaly'
);

CREATE TYPE response_status AS ENUM (
    'pending', 'approved', 'executing', 'completed', 'failed', 'rejected'
);

CREATE TYPE agent_status AS ENUM (
    'active', 'inactive', 'error', 'decommissioned'
);

CREATE TYPE run_status AS ENUM (
    'pending', 'running', 'completed', 'failed', 'cancelled'
);

CREATE TYPE model_lifecycle AS ENUM (
    'trained', 'evaluated', 'promoted', 'deprecated'
);

-- =============================================================================
-- Core Tables
-- =============================================================================

-- Users (SOC analysts, administrators)
CREATE TABLE users (
    user_id         VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    username        VARCHAR(255) UNIQUE NOT NULL,
    email           VARCHAR(255) UNIQUE NOT NULL,
    display_name    VARCHAR(255),
    role            VARCHAR(50) NOT NULL DEFAULT 'analyst',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Endpoints (monitored systems)
CREATE TABLE endpoints (
    endpoint_id     VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    hostname        VARCHAR(255) NOT NULL,
    ip_address      INET,
    os              VARCHAR(100),
    os_version      VARCHAR(100),
    agent_version   VARCHAR(50),
    status          agent_status NOT NULL DEFAULT 'active',
    environment     VARCHAR(100) DEFAULT 'unknown',
    asset_criticality VARCHAR(50) DEFAULT 'unknown',
    department      VARCHAR(100),
    last_seen       TIMESTAMPTZ,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata        JSONB DEFAULT '{}'::jsonb,
    UNIQUE(hostname, ip_address)
);

CREATE INDEX idx_endpoints_hostname ON endpoints(hostname);
CREATE INDEX idx_endpoints_status ON endpoints(status);

-- Agent instances (endpoint telemetry agents)
CREATE TABLE agents (
    agent_id        VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    endpoint_id     VARCHAR(64) NOT NULL REFERENCES endpoints(endpoint_id),
    agent_type      VARCHAR(50) NOT NULL DEFAULT 'telemetry',
    version         VARCHAR(50),
    status          agent_status NOT NULL DEFAULT 'active',
    last_heartbeat  TIMESTAMPTZ,
    config          JSONB DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_endpoint ON agents(endpoint_id);

-- =============================================================================
-- Telemetry & Events
-- =============================================================================

-- Events (normalized security events from endpoint telemetry)
CREATE TABLE events (
    event_id        VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    source_event_id VARCHAR(255),
    endpoint_id     VARCHAR(64) REFERENCES endpoints(endpoint_id),
    event_type      VARCHAR(50) NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname        VARCHAR(255),
    username        VARCHAR(255),
    source_ip       INET,
    dest_ip         INET,
    domain          VARCHAR(255),
    process_name    VARCHAR(255),
    command_line    TEXT,
    file_path       TEXT,
    file_hash       VARCHAR(128),
    port            INTEGER,
    dest_port       INTEGER,
    protocol        VARCHAR(20),
    severity        alert_severity,
    source_name     VARCHAR(100),
    source_format   VARCHAR(20),
    fingerprint     VARCHAR(64),
    raw             JSONB DEFAULT '{}'::jsonb,
    attributes      JSONB DEFAULT '{}'::jsonb,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_endpoint ON events(endpoint_id);
CREATE INDEX idx_events_event_type ON events(event_type);
CREATE INDEX idx_events_hostname ON events(hostname);
CREATE INDEX idx_events_source_ip ON events USING btree(source_ip);
CREATE INDEX idx_events_fingerprint ON events(fingerprint);

-- Processes (process tree data from endpoint telemetry)
CREATE TABLE processes (
    process_id      VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    event_id        VARCHAR(64) REFERENCES events(event_id),
    endpoint_id     VARCHAR(64) REFERENCES endpoints(endpoint_id),
    pid             INTEGER,
    parent_pid      INTEGER,
    process_name    VARCHAR(255),
    command_line    TEXT,
    file_path       TEXT,
    file_hash       VARCHAR(128),
    username        VARCHAR(255),
    start_time      TIMESTAMPTZ,
    end_time        TIMESTAMPTZ,
    integrity_level VARCHAR(50),
    is_elevated     BOOLEAN DEFAULT false,
    metadata        JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_processes_event ON processes(event_id);
CREATE INDEX idx_processes_endpoint ON processes(endpoint_id);
CREATE INDEX idx_processes_pid ON processes(endpoint_id, pid);

-- Network events (network connection telemetry)
CREATE TABLE network_events (
    network_event_id VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    event_id        VARCHAR(64) REFERENCES events(event_id),
    endpoint_id     VARCHAR(64) REFERENCES endpoints(endpoint_id),
    source_ip       INET,
    dest_ip         INET,
    source_port     INTEGER,
    dest_port       INTEGER,
    protocol        VARCHAR(20),
    direction       VARCHAR(20),
    bytes_sent      BIGINT,
    bytes_received  BIGINT,
    packets_sent    BIGINT,
    packets_received BIGINT,
    duration_ms     INTEGER,
    dns_query       VARCHAR(255),
    tls_sni         VARCHAR(255),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata        JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_network_events_event ON network_events(event_id);
CREATE INDEX idx_network_events_dest_ip ON network_events USING btree(dest_ip);
CREATE INDEX idx_network_events_dest_port ON network_events(dest_port);

-- =============================================================================
-- Detection & Correlation
-- =============================================================================

-- Alerts (produced by the detection engine)
CREATE TABLE alerts (
    alert_id        VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        alert_severity NOT NULL DEFAULT 'medium',
    status          alert_status NOT NULL DEFAULT 'new',
    detection_type  detection_type NOT NULL DEFAULT 'rule',
    rule_id         VARCHAR(50),
    rule_name       VARCHAR(255),
    source_event_id VARCHAR(64) REFERENCES events(event_id),
    hostname        VARCHAR(255),
    username        VARCHAR(255),
    source_ip       INET,
    dest_ip         INET,
    process_name    VARCHAR(255),
    command_line    TEXT,
    file_path       TEXT,
    mitre_technique_id VARCHAR(20),
    mitre_technique_name VARCHAR(255),
    mitre_tactic    VARCHAR(100),
    evidence        JSONB DEFAULT '{}'::jsonb,
    match_details   TEXT,
    classification  classification_type,
    confidence      REAL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX idx_alerts_created_at ON alerts(created_at);
CREATE INDEX idx_alerts_hostname ON alerts(hostname);
CREATE INDEX idx_alerts_mitre ON alerts(mitre_technique_id);

-- Incidents (correlated groups of related alerts)
CREATE TABLE incidents (
    incident_id     VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        incident_severity NOT NULL DEFAULT 'medium',
    status          incident_status NOT NULL DEFAULT 'new',
    alert_count     INTEGER NOT NULL DEFAULT 0,
    affected_hosts  TEXT[] DEFAULT '{}',
    affected_users  TEXT[] DEFAULT '{}',
    affected_ips    TEXT[] DEFAULT '{}',
    attack_stages   TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',
    is_multi_stage  BOOLEAN DEFAULT false,
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    correlation_method VARCHAR(100),
    correlation_window_minutes INTEGER DEFAULT 30,
    assigned_to     VARCHAR(64) REFERENCES users(user_id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_created_at ON incidents(created_at);

-- Incident-Alert junction table
CREATE TABLE incident_events (
    incident_id     VARCHAR(64) NOT NULL REFERENCES incidents(incident_id),
    alert_id        VARCHAR(64) NOT NULL REFERENCES alerts(alert_id),
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (incident_id, alert_id)
);

-- =============================================================================
-- AI Investigation & Triage
-- =============================================================================

-- Investigations (AI-driven investigation sessions)
CREATE TABLE investigations (
    investigation_id VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    incident_id     VARCHAR(64) NOT NULL REFERENCES incidents(incident_id),
    agent_type      VARCHAR(50) NOT NULL DEFAULT 'investigation',
    status          VARCHAR(50) NOT NULL DEFAULT 'in_progress',
    classification  classification_type,
    confidence      REAL,
    summary         TEXT,
    total_steps     INTEGER DEFAULT 0,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    metadata        JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_investigations_incident ON investigations(incident_id);

-- Investigation steps (individual tool calls / reasoning steps)
CREATE TABLE investigation_steps (
    step_id         VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    investigation_id VARCHAR(64) NOT NULL REFERENCES investigations(investigation_id),
    step_number     INTEGER NOT NULL,
    action          VARCHAR(100) NOT NULL,
    tool_name       VARCHAR(100),
    tool_input      JSONB DEFAULT '{}'::jsonb,
    tool_output     JSONB DEFAULT '{}'::jsonb,
    reasoning       TEXT,
    findings        JSONB DEFAULT '[]'::jsonb,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_investigation_steps_investigation ON investigation_steps(investigation_id);

-- =============================================================================
-- Threat Intelligence & MITRE
-- =============================================================================

-- Threat intelligence records
CREATE TABLE threat_intelligence (
    ti_id           VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    indicator_type  VARCHAR(50) NOT NULL,
    indicator_value VARCHAR(500) NOT NULL,
    threat_type     VARCHAR(100),
    reputation      VARCHAR(50),
    confidence      REAL DEFAULT 0.0,
    source          VARCHAR(255),
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    description     TEXT,
    tags            TEXT[] DEFAULT '{}',
    metadata        JSONB DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ti_indicator ON threat_intelligence(indicator_type, indicator_value);
CREATE INDEX idx_ti_reputation ON threat_intelligence(reputation);

-- MITRE ATT&CK tactics
CREATE TABLE mitre_tactics (
    tactic_id       VARCHAR(20) PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    url             VARCHAR(500),
    kill_chain_order INTEGER
);

-- MITRE ATT&CK techniques
CREATE TABLE mitre_techniques (
    technique_id    VARCHAR(20) PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    url             VARCHAR(500),
    is_subtechnique BOOLEAN DEFAULT false,
    parent_id       VARCHAR(20) REFERENCES mitre_techniques(technique_id),
    platforms       TEXT[] DEFAULT '{}',
    detection       TEXT
);

-- MITRE tactic-technique mappings
CREATE TABLE mitre_mappings (
    mapping_id      VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    tactic_id       VARCHAR(20) NOT NULL REFERENCES mitre_tactics(tactic_id),
    technique_id    VARCHAR(20) NOT NULL REFERENCES mitre_techniques(technique_id),
    UNIQUE(tactic_id, technique_id)
);

-- Entity relationships (for attack graph construction)
CREATE TABLE entity_relationships (
    relationship_id VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    source_type     VARCHAR(50) NOT NULL,
    source_id       VARCHAR(255) NOT NULL,
    target_type     VARCHAR(50) NOT NULL,
    target_id       VARCHAR(255) NOT NULL,
    relationship    VARCHAR(100) NOT NULL,
    confidence      REAL DEFAULT 1.0,
    evidence_id     VARCHAR(64),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata        JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_entity_rel_source ON entity_relationships(source_type, source_id);
CREATE INDEX idx_entity_rel_target ON entity_relationships(target_type, target_id);

-- =============================================================================
-- RAG Document Store
-- =============================================================================

-- Document chunks for RAG retrieval (with pgvector embeddings)
CREATE TABLE document_chunks (
    chunk_id        VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    document_title  VARCHAR(500) NOT NULL,
    document_source VARCHAR(255),
    chunk_index     INTEGER NOT NULL DEFAULT 0,
    content         TEXT NOT NULL,
    embedding       vector(384),
    metadata        JSONB DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_chunks_source ON document_chunks(document_source);
-- Create HNSW index for vector similarity search
-- CREATE INDEX idx_chunks_embedding ON document_chunks USING hnsw (embedding vector_cosine_ops);

-- =============================================================================
-- Response & Containment
-- =============================================================================

-- Responses (AI-recommended + human-approved response actions)
CREATE TABLE responses (
    response_id     VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    incident_id     VARCHAR(64) NOT NULL REFERENCES incidents(incident_id),
    recommended_by  VARCHAR(50) DEFAULT 'ai_agent',
    status          response_status NOT NULL DEFAULT 'pending',
    approved_by     VARCHAR(64) REFERENCES users(user_id),
    approved_at     TIMESTAMPTZ,
    summary         TEXT,
    risk_score      REAL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at     TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_responses_incident ON responses(incident_id);
CREATE INDEX idx_responses_status ON responses(status);

-- Individual response actions within a response plan
CREATE TABLE response_actions (
    action_id       VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    response_id     VARCHAR(64) NOT NULL REFERENCES responses(response_id),
    action_type     VARCHAR(100) NOT NULL,
    description     TEXT NOT NULL,
    priority        VARCHAR(20) DEFAULT 'medium',
    target_endpoint VARCHAR(64) REFERENCES endpoints(endpoint_id),
    parameters      JSONB DEFAULT '{}'::jsonb,
    status          response_status NOT NULL DEFAULT 'pending',
    result          JSONB DEFAULT '{}'::jsonb,
    executed_at     TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_response_actions_response ON response_actions(response_id);

-- Verification results (post-response verification)
CREATE TABLE verification_results (
    verification_id VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    response_id     VARCHAR(64) NOT NULL REFERENCES responses(response_id),
    incident_id     VARCHAR(64) NOT NULL REFERENCES incidents(incident_id),
    verified_by     VARCHAR(50) DEFAULT 'verification_agent',
    is_effective    BOOLEAN,
    findings        JSONB DEFAULT '[]'::jsonb,
    recommendations JSONB DEFAULT '[]'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verification_response ON verification_results(response_id);

-- =============================================================================
-- Agent Traces & Audit
-- =============================================================================

-- Agent execution traces (LLM call audit trail)
CREATE TABLE agent_traces (
    trace_id        VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    agent_type      VARCHAR(50) NOT NULL,
    investigation_id VARCHAR(64) REFERENCES investigations(investigation_id),
    incident_id     VARCHAR(64) REFERENCES incidents(incident_id),
    model           VARCHAR(255),
    provider        VARCHAR(100),
    input_tokens    INTEGER,
    output_tokens   INTEGER,
    latency_ms      REAL,
    request_prompt  TEXT,
    response_content TEXT,
    structured_output JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_traces_investigation ON agent_traces(investigation_id);
CREATE INDEX idx_agent_traces_agent_type ON agent_traces(agent_type);

-- Feedback (analyst feedback on AI decisions)
CREATE TABLE feedback (
    feedback_id     VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    user_id         VARCHAR(64) NOT NULL REFERENCES users(user_id),
    investigation_id VARCHAR(64) REFERENCES investigations(investigation_id),
    alert_id        VARCHAR(64) REFERENCES alerts(alert_id),
    incident_id     VARCHAR(64) REFERENCES incidents(incident_id),
    feedback_type   VARCHAR(50) NOT NULL,
    rating          INTEGER CHECK (rating >= 1 AND rating <= 5),
    correct_classification classification_type,
    comments        TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_feedback_user ON feedback(user_id);

-- Audit log (immutable action log)
CREATE TABLE audit_logs (
    log_id          VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    user_id         VARCHAR(64) REFERENCES users(user_id),
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(50),
    resource_id     VARCHAR(64),
    details         JSONB DEFAULT '{}'::jsonb,
    ip_address      INET,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-- =============================================================================
-- Training & Dataset Provenance
-- =============================================================================

-- Training examples (labeled examples for fine-tuning)
CREATE TABLE training_examples (
    example_id      VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    source          VARCHAR(100) NOT NULL,
    split           VARCHAR(20) NOT NULL DEFAULT 'train',
    messages        JSONB NOT NULL,
    classification  classification_type,
    task_type       VARCHAR(50),
    quality_score   REAL,
    is_protected    BOOLEAN DEFAULT false,
    dataset_version VARCHAR(50),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_training_examples_source ON training_examples(source);
CREATE INDEX idx_training_examples_split ON training_examples(split);
CREATE INDEX idx_training_examples_version ON training_examples(dataset_version);

-- Dataset provenance (source lineage tracking)
CREATE TABLE dataset_provenance (
    provenance_id   VARCHAR(64) PRIMARY KEY DEFAULT uuid_generate_v4()::text,
    record_id       VARCHAR(255) NOT NULL,
    source_dataset  VARCHAR(255) NOT NULL,
    source_file     VARCHAR(500),
    source_record_id VARCHAR(255),
    source_label    VARCHAR(255),
    canonical_label classification_type,
    transformation_version VARCHAR(50),
    quality_score   REAL,
    status          VARCHAR(50) DEFAULT 'processed',
    harmonization_status VARCHAR(50),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_provenance_record ON dataset_provenance(record_id);
CREATE INDEX idx_provenance_source ON dataset_provenance(source_dataset);

-- =============================================================================
-- Updated-at trigger function
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at triggers
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alerts_updated_at BEFORE UPDATE ON alerts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_incidents_updated_at BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_ti_updated_at BEFORE UPDATE ON threat_intelligence
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
