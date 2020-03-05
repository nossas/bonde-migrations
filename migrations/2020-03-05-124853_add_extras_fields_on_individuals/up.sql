ALTER TABLE public.rede_individuals ADD COLUMN extras JSONB;
ALTER TABLE public.rede_individuals DROP COLUMN register_occupation;
ALTER TABLE public.rede_individuals DROP COLUMN field_occupation;