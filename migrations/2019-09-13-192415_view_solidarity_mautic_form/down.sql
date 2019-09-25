-- This file should undo anything in `up.sql`
DROP VIEW solidarity_mautic_form;

ALTER TABLE solidarity_zd_tickets DROP COLUMN webhooks_registry_id;