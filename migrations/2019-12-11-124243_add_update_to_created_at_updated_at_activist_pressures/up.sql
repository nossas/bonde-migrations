ALTER TABLE public.activist_pressures ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE public.activist_pressures ALTER COLUMN updated_at SET DEFAULT now();

DROP TRIGGER IF EXISTS activist_pressures_update_at ON public.activist_pressures;

CREATE TRIGGER activist_pressures_update_at BEFORE UPDATE ON activist_pressures FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();


ALTER TABLE public.activists ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE public.activists ALTER COLUMN updated_at SET DEFAULT now();

DROP TRIGGER IF EXISTS activists_update_at ON public.activists;

CREATE TRIGGER activists_update_at BEFORE UPDATE ON activists FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();