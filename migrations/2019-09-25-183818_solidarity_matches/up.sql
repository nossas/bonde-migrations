-- Your SQL goes here
CREATE TABLE solidarity_matches (
    id SERIAL PRIMARY KEY,
    msr_ticket INTEGER REFERENCES solidarity_zd_tickets(id),
    voluntaria_ticket INTEGER REFERENCES solidarity_zd_tickets(id),
    UNIQUE(msr_ticket),
    UNIQUE(voluntaria_ticket)
);