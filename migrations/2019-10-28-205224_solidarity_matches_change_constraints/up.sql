-- Your SQL goes here-- Your SQL goes here
ALTER TABLE solidarity_matches DROP CONSTRAINT solidarity_matches_individuals_user_id_volunteers_user_id_key;
ALTER TABLE solidarity_matches DROP CONSTRAINT solidarity_matches_individuals_ticket_id_key;
ALTER TABLE solidarity_matches DROP CONSTRAINT solidarity_matches_volunteers_ticket_id_key;
ALTER TABLE solidarity_matches ADD UNIQUE (individuals_ticket_id, volunteers_ticket_id);