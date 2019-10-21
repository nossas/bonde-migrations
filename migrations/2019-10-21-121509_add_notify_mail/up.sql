CREATE SEQUENCE notify_mail_id_seq start 1 increment 1;

create table public.notify_mail (
    id integer not null primary key default nextval('notify_mail_id_seq'),
    email_from varchar not null,
    email_to varchar not null,
    context jsonb,
    subject varchar not null,
    body varchar not null,
    created_at timestamp without time zone not null default now(),
    updated_at timestamp without time zone default now(),
    delivered_at timestamp without time zone
);

COMMENT ON TABLE public.notify_mail
    IS 'Tabela responsável por registrar envios de e-mail';

CREATE TRIGGER notify_mail_update_at
    BEFORE UPDATE 
    ON public.notify_mail
    FOR EACH ROW
    EXECUTE PROCEDURE public.updated_at_column();