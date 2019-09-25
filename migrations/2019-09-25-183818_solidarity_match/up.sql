-- Your SQL goes here
CREATE TABLE solidarity_match (
    id SERIAL PRIMARY KEY,
    msr_ticket INTEGER REFERENCES solidarity_zd_tickets(id),
    voluntaria_ticket INTEGER REFERENCES solidarity_zd_tickets(id),
    UNIQUE(msr_ticket),
    UNIQUE(msr_ticket, voluntaria_ticket)
);