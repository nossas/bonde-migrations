-- Your SQL goes here
CREATE TABLE zendesk_tickets (
    id SERIAL PRIMARY KEY,
    assignee_id BIGINT,
    created_at TIMESTAMP,
    custom_fields JSONB,
    description TEXT,
    group_id BIGINT,
    ticket_id BIGINT UNIQUE NOT NULL,
    organization_id BIGINT,
    raw_subject TEXT,
    requester_id BIGINT,
    status TEXT,
    subject TEXT,
    submitter_id BIGINT,
    tags JSONB,
    updated_at TIMESTAMP
);