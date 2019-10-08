-- Torna activists.email um campo único para facilitar resolução de conflito no Hasura
ALTER TABLE public.activists ADD CONSTRAINT activists_email_key UNIQUE (email);

-- Atualiza campos como created_at e updated_at pra facilitar preenchimento dos campos
ALTER TABLE activist_pressures ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE activist_pressures ALTER COLUMN updated_at SET DEFAULT now();

CREATE TRIGGER activist_pressures_update_at BEFORE UPDATE ON activist_pressures FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();

COMMENT ON TABLE public.activist_pressures
    IS 'Tabela responsável por relacionar módulo Pressão com o módulo Ativista';

ALTER TABLE activists ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE activists ALTER COLUMN updated_at SET DEFAULT now();

CREATE TRIGGER activists_update_at BEFORE UPDATE ON activists FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();

COMMENT ON TABLE public.activists
    IS 'Tabela responsável pelo módulo de Ativistas, agrupado por ações de ativistas em canais do Bonde';