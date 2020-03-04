-- Revert new column
ALTER TABLE public.form_entries DROP COLUMN rede_syncronized;

-- Revert drop table
CREATE TABLE public.rede_settings
(
	created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone DEFAULT now(),
  id integer NOT NULL DEFAULT nextval('rede_settings_id_seq'::regclass),
  settings jsonb NOT NULL,
  community_id integer NOT NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (community_id)
      REFERENCES public.communities (id) MATCH SIMPLE
      ON UPDATE NO ACTION
      ON DELETE NO ACTION
)
WITH (
    OIDS = FALSE
);

CREATE TRIGGER rede_settings_update_at BEFORE UPDATE ON rede_settings FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();

COMMENT ON TABLE public.rede_settings
    IS 'Tabela responsável por armazenar as configurações do módulo rede';