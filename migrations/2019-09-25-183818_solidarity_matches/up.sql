-- Your SQL goes here
CREATE TABLE solidarity_matches (
    id SERIAL PRIMARY KEY,
    individuals_ticket_id INTEGER REFERENCES solidarity_tickets(id),
    volunteers_ticket_id INTEGER REFERENCES solidarity_tickets(id),
    individuals_user_id INTEGER REFERENCES solidarity_users(id),
    volunteers_user_id INTEGER REFERENCES solidarity_users(id),
    community_id INTEGER REFERENCES communities(id),
    UNIQUE(individuals_ticket_id),
    UNIQUE(volunteers_ticket_id),
    UNIQUE(individuals_user_id, volunteers_user_id)
);