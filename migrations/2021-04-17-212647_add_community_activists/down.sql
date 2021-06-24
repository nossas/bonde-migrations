-- This file should undo anything in `up.sql`
ALTER TABLE public.activists DROP COLUMN community_id;
ALTER TABLE public.activists DROP COLUMN events_data_form_entries;
ALTER TABLE public.activists DROP COLUMN events_data_donations;
ALTER TABLE public.activists DROP COLUMN events_data_pressure;