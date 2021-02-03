ALTER TABLE public.rede_individuals ADD COLUMN name VARCHAR NOT NULL;

ALTER TABLE public.rede_individuals DROP COLUMN first_name;
ALTER TABLE public.rede_individuals DROP COLUMN last_name;