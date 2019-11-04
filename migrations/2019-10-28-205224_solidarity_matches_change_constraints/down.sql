-- This file should undo anything in `up.sql`
ALTER TABLE solidarity_matches DROP CONSTRAINT solidarity_matches_individuals_ticket_id_volunteers_ticket__key;
ALTER TABLE solidarity_matches ADD UNIQUE (individuals_user_id, volunteers_user_id);
ALTER TABLE solidarity_matches ADD UNIQUE (individuals_ticket_id);
ALTER TABLE solidarity_matches ADD UNIQUE (volunteers_ticket_id);