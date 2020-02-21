-- Your SQL goes here

-- rede_groups
-- DROP TABLE public.rede_groups;
-- DROP SEQUENCE public.rede_groups_id_seq;
CREATE SEQUENCE rede_groups_id_seq
 INCREMENT 1
 MINVALUE 1
 START 1
 CACHE 1;

CREATE TABLE public.rede_groups
(
	created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone DEFAULT now(),
  id integer NOT NULL DEFAULT nextval('rede_groups_id_seq'::regclass),
  name text NOT NULL,
  is_volunteer boolean NOT NULL DEFAULT false,
  community_id integer NOT NULL,
  widget_id integer NOT NULL,
  metadata jsonb NOT NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (community_id)
      REFERENCES public.communities (id) MATCH SIMPLE
      ON UPDATE NO ACTION
      ON DELETE NO ACTION,
  FOREIGN KEY (widget_id)
      REFERENCES public.widgets (id) MATCH SIMPLE
      ON UPDATE NO ACTION
      ON DELETE NO ACTION
)
WITH (
    OIDS = FALSE
);

CREATE TRIGGER rede_groups_update_at BEFORE UPDATE ON rede_groups FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();

COMMENT ON TABLE public.rede_groups
    IS 'Tabela responsável por relacionar módulo Rede com Comunidade e Widget';


-- rede_individuals
-- DROP TABLE public.rede_individuals;
-- DROP SEQUENCE public.rede_individuals_id_seq;
CREATE SEQUENCE rede_individuals_id_seq
 INCREMENT 1
 MINVALUE 1
 START 1
 CACHE 1;

CREATE TABLE public.rede_individuals
(
	created_at timestamp without time zone NOT NULL DEFAULT now(),
  updated_at timestamp without time zone DEFAULT now(),
  id integer NOT NULL DEFAULT nextval('rede_individuals_id_seq'::regclass),
  name text NOT NULL,
  email text NOT NULL,
  phone text NOT NULL,
  address text NOT NULL,
  city text NOT NULL,
  state text NOT NULL,
  latitude text NOT NULL,
  longitude text NOT NULL,
  register_occupation text NOT NULL,
  whatsapp text NOT NULL,
  field_occupation text NOT NULL,
  rede_group_id integer NOT NULL,
  form_entry_id integer NOT NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (rede_group_id)
      REFERENCES public.rede_groups (id) MATCH SIMPLE
      ON UPDATE NO ACTION
      ON DELETE NO ACTION,
  FOREIGN KEY (form_entry_id)
      REFERENCES public.form_entries (id) MATCH SIMPLE
      ON UPDATE NO ACTION
      ON DELETE NO ACTION
)
WITH (
    OIDS = FALSE
);

CREATE TRIGGER rede_individuals_update_at BEFORE UPDATE ON rede_individuals FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();

COMMENT ON TABLE public.rede_individuals
    IS 'Tabela responsável por armazenar os indivíduos da rede separados por grupo';


-- ChatbotCampaign
-- DROP TABLE public.rede_relationships;
-- DROP SEQUENCE public.rede_relationships_id_seq;

CREATE SEQUENCE rede_relationships_id_seq
 INCREMENT 1
 MINVALUE 1
 START 1
 CACHE 1;

CREATE TABLE public.rede_relationships
(
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    id integer NOT NULL DEFAULT nextval('rede_relationships_id_seq'::regclass),
    is_archived boolean DEFAULT false,
    comments TEXT NULL,
    status TEXT NOT NULL,
    priority integer NOT NULL DEFAULT 0,
    metadata jsonb NULL,
    volunteer_id integer NOT NULL,
    recipient_id integer NOT NULL,
    user_id integer NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (volunteer_id)
        REFERENCES public.rede_individuals (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION,
    FOREIGN KEY (recipient_id)
        REFERENCES public.rede_individuals (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION,
    FOREIGN KEY (user_id)
        REFERENCES public.users (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION

)
WITH (
    OIDS = FALSE
);

CREATE TRIGGER rede_relationships_update_at BEFORE UPDATE ON rede_relationships FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();

COMMENT ON TABLE public.rede_relationships
    IS 'Tabela responsável por armazenar acompanhamento de um relacionamento seja com a inscrição na rede, seja entre voluntário e beneficiário.';


-- RedeSettings
-- DROP TABLE public.rede_settings;
-- DROP SEQUENCE public.rede_settings_id_seq;
CREATE SEQUENCE rede_settings_id_seq
 INCREMENT 1
 MINVALUE 1
 START 1
 CACHE 1;

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