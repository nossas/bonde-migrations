-- Your SQL goes here
CREATE TABLE solidarity_matches (
    id SERIAL PRIMARY KEY,
    individuals_ticket_id BIGINT REFERENCES solidarity_tickets(ticket_id),
    volunteers_ticket_id BIGINT REFERENCES solidarity_tickets(ticket_id),
    individuals_user_id BIGINT REFERENCES solidarity_users(user_id),
    volunteers_user_id BIGINT REFERENCES solidarity_users(user_id),
    community_id INTEGER REFERENCES communities(id),
    created_at TIMESTAMP NOT NULL,
    status TEXT,
    UNIQUE(individuals_ticket_id),
    UNIQUE(volunteers_ticket_id),
    UNIQUE(individuals_user_id, volunteers_user_id)
);