ALTER TABLE public.rede_individuals ADD COLUMN coordinates JSONB;

ALTER TABLE public.rede_individuals DROP COLUMN latitude;
ALTER TABLE public.rede_individuals DROP COLUMN longitude;

ALTER TABLE public.rede_individuals ALTER COLUMN address DROP NOT NULL;
ALTER TABLE public.rede_individuals ADD COLUMN zipcode VARCHAR(8) NOT NULL;