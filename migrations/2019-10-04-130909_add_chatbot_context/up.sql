-- Your SQL goes here

-- add a chatbot_interactions to create context bot
CREATE SEQUENCE chatbot_interactions_id_seq
 INCREMENT 1
 MINVALUE 1
 START 1
 CACHE 1;

CREATE TABLE public.chatbot_interactions
(
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    id integer NOT NULL DEFAULT nextval('chatbot_interactions_id_seq'::regclass),
    interaction jsonb NOT NULL,
    chatbot_id integer NOT NULL,
    context_recipient_id text NOT NULL,
	context_sender_id text NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (chatbot_id)
        REFERENCES public.chatbots (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)
WITH (
    OIDS = FALSE
);

CREATE TRIGGER chatbots_interactions_update_at BEFORE UPDATE ON chatbot_interactions FOR EACH ROW EXECUTE PROCEDURE  updated_at_column();

COMMENT ON TABLE public.chatbot_interactions
    IS 'Tabela responsável por contextualizar interações entre o bot e o usuário';


-- Fix permissions on postgraphql.users
GRANT SELECT ON TABLE postgraphql.users TO admin;