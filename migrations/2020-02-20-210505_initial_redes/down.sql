-- This file should undo anything in `up.sql`
DROP TRIGGER rede_groups_update_at ON rede_groups;
DROP TRIGGER rede_individuals_update_at ON rede_individuals;
DROP TRIGGER rede_relationships_update_at ON rede_relationships;
DROP TRIGGER rede_settings_update_at ON rede_settings;

DROP TABLE public.rede_groups;
DROP TABLE public.rede_individuals;
DROP TABLE public.rede_relationships;
DROP TABLE public.rede_settings;

DROP SEQUENCE public.rede_groups_id_seq;
DROP SEQUENCE public.rede_individuals_id_seq;
DROP SEQUENCE public.rede_relationships_id_seq;
DROP SEQUENCE public.rede_settings_id_seq;