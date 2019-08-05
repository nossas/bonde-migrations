-- Your SQL goes here

-- Function to updated_at column
CREATE OR REPLACE FUNCTION updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';


-- Chatbot
-- DROP TABLE public.chatbot;
-- DROP SEQUENCE public.chatbot_id_seq;
CREATE SEQUENCE chatbots_id_seq
 INCREMENT 1
 MINVALUE 1
 START 1
 CACHE 1;

CREATE TABLE public.chatbots
(
	created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    id integer NOT NULL DEFAULT nextval('chatbots_id_seq'::regclass),
    name text NOT NULL,
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

CREATE TRIGGER chatbots_update_at BEFORE UPDATE ON chatbots FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();

ALTER TABLE public.chatbots
    OWNER to monkey_user;
COMMENT ON TABLE public.chatbots
    IS 'Tabela responsável por relacionar módulo Chatbot com módulo Comunidade';


-- ChatbotCampaign
-- DROP TABLE public.chatbot_campaigns;
-- DROP SEQUENCE public.chatbot_campaigns_id_seq;

CREATE SEQUENCE chatbot_campaigns_id_seq
 INCREMENT 1
 MINVALUE 1
 START 1
 CACHE 1;

CREATE TABLE public.chatbot_campaigns
(
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    id integer NOT NULL DEFAULT nextval('chatbot_campaigns_id_seq'::regclass),
    name character varying COLLATE pg_catalog."default" NOT NULL,
    draft boolean DEFAULT false,
    diagram jsonb NOT NULL,
    chatbot_id integer NOT NULL,
    prefix text UNIQUE NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (chatbot_id)
        REFERENCES public.chatbots (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)
WITH (
    OIDS = FALSE
);

CREATE TRIGGER chatbots_campaigns_update_at BEFORE UPDATE ON chatbot_campaigns FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();

ALTER TABLE public.chatbot_campaigns
    OWNER to monkey_user;
COMMENT ON TABLE public.chatbot_campaigns
    IS 'Tabela responsável por armazenar fluxos de conversa de um Chatbot';


-- ChatbotSettings
-- DROP TABLE public.chatbot_settings;
-- DROP SEQUENCE public.chatbot_settings_id_seq;
CREATE SEQUENCE chatbot_settings_id_seq
 INCREMENT 1
 MINVALUE 1
 START 1
 CACHE 1;

CREATE TABLE public.chatbot_settings
(
	created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    id integer NOT NULL DEFAULT nextval('chatbot_settings_id_seq'::regclass),
    channel text NOT NULL,
    settings jsonb NOT NULL,
    chatbot_id integer NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (chatbot_id)
        REFERENCES public.chatbots (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)
WITH (
    OIDS = FALSE
);

CREATE TRIGGER chatbots_settings_update_at BEFORE UPDATE ON chatbot_settings FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();

ALTER TABLE public.chatbot_settings
    OWNER to monkey_user;
COMMENT ON TABLE public.chatbot_settings
    IS 'Tabela responsável por armazenar as configurações dos canais usados para comunicação de um Chatbot';
