-- Add column mobilization_id to actions tables
alter table public.form_entries add column mobilization_id integer;
alter table public.activist_pressures add column mobilization_id integer;
alter table public.donations add column mobilization_id integer;

-- Add table pressure_targets
CREATE TABLE public.pressure_targets
(
    id integer NOT NULL,
    widget_id integer NOT NULL,
    targets jsonb,
    identify character varying NOT NULL,
    label character varying NOT NULL,
		email_subject character varying,
		email_body character varying,
    PRIMARY KEY (id),
    CONSTRAINT unique_identify_widget_id UNIQUE (widget_id, identify),
    CONSTRAINT fk_pressure_targets_widget FOREIGN KEY (widget_id)
        REFERENCES public.widgets (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
)
WITH (
    OIDS = FALSE
);

CREATE SEQUENCE pressure_targets_id_seq
  start 1
  increment 1;

ALTER TABLE public.pressure_targets
    ALTER COLUMN id SET DEFAULT nextval('pressure_targets_id_seq'::regclass);