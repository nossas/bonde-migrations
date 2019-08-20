CREATE SEQUENCE webhooks_record_id_seq
    INCREMENT 1
    MINVALUE 1
    START 1
    CACHE 1;

CREATE TABLE public.webhooks_record (
    id integer NOT NULL DEFAULT nextval('webhooks_record_id_seq'::regclass),
    data jsonb NOT NULL,
    service_name character varying COLLATE pg_catalog."default" NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT webhook_logs_pkey PRIMARY KEY (id)
);