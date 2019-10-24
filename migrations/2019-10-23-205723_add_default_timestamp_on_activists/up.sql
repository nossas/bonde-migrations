ALTER TABLE public.activists ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE public.activists ALTER COLUMN updated_at SET DEFAULT now();

CREATE TRIGGER activists_update_at
    BEFORE UPDATE 
    ON public.activists
    FOR EACH ROW
    EXECUTE PROCEDURE public.updated_at_column();

ALTER TABLE public.activist_pressures ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE public.activist_pressures ALTER COLUMN updated_at SET DEFAULT now();

CREATE TRIGGER activist_pressures_update_at
    BEFORE UPDATE 
    ON public.activist_pressures
    FOR EACH ROW
    EXECUTE PROCEDURE public.updated_at_column();