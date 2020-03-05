ALTER TABLE public.rede_individuals DROP COLUMN coordinates JSONB;

ALTER TABLE public.rede_individuals ADD COLUMN latitude VARCHAR;
ALTER TABLE public.rede_individuals ADD COLUMN longitude VARCHAR;

ALTER TABLE public.rede_individuals DROP COLUMN zipcode;
ALTER TABLE public.rede_individuals ALTER COLUMN address SET NOT NULL;
