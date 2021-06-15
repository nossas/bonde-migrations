-- Your SQL goes here
ALTER TABLE public.activists
ADD COLUMN community_id int;
ALTER TABLE public.activists
ADD COLUMN events_data_form_entries jsonb;
ALTER TABLE public.activists
ADD COLUMN events_data_donations jsonb;
ALTER TABLE public.activists
ADD COLUMN events_data_pressure jsonb;
ALTER TABLE public.activists
ADD COLUMN events_data_pressure jsonb;
ALTER TABLE public.activists
ADD COLUMN whatsapp;