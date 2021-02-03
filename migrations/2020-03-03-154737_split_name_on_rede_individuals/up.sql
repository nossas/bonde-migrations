ALTER TABLE public.rede_individuals DROP COLUMN name;

ALTER TABLE public.rede_individuals ADD COLUMN first_name VARCHAR NOT NULL;
ALTER TABLE public.rede_individuals ADD COLUMN last_name VARCHAR;