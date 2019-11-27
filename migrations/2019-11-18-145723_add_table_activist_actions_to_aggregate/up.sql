-- Drop old view to aggregate actions
DROP VIEW public.activist_actions;
COMMIT;
-- Re-create activist_actions like table to use max of performance of Hasura
CREATE SEQUENCE activist_actions_id_seq
 INCREMENT 1
 MINVALUE 1
 START 1
 CACHE 1;

CREATE TABLE public.activist_actions
(
	action_created_at timestamp without time zone NOT NULL,
    activist_created_at timestamp without time zone NOT NULL,
    id integer NOT NULL DEFAULT nextval('activist_actions_id_seq'::regclass),
    action text NOT NULL,
    widget_id integer NOT NULL,
	mobilization_id integer NOT NULL,
	community_id integer NOT NULL,
	activist_id integer NOT NULL,
    PRIMARY KEY (id),
	FOREIGN KEY (community_id)
        REFERENCES public.communities (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION,
    FOREIGN KEY (mobilization_id)
        REFERENCES public.mobilizations (id) MATCH SIMPLE
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

COMMENT ON TABLE public.activist_actions
    IS 'Tabela responsável por agregar informações sobre as ações do ativista';

COMMIT;
-- Update table with old actions, now use trigger to update table activist_actions
INSERT INTO public.activist_actions(action, widget_id, mobilization_id, community_id, activist_id, action_created_at, activist_created_at)
SELECT 'activist_pressures'::text AS action,
	w.id AS widget_id,
	m.id AS mobilization_id,
	m.community_id,
	fe.activist_id,
	fe.created_at AS action_created_date,
	a.created_at AS activist_created_at
   FROM activist_pressures fe
	 JOIN activists a ON a.id = fe.activist_id
	 JOIN widgets w ON w.id = fe.widget_id
	 JOIN blocks b ON b.id = w.block_id
	 JOIN mobilizations m ON m.id = b.mobilization_id;
COMMIT;
INSERT INTO public.activist_actions(action, widget_id, mobilization_id, community_id, activist_id, action_created_at, activist_created_at)
SELECT 'form_entries'::text AS action,
	w.id AS widget_id,
	m.id AS mobilization_id,
	m.community_id,
	fe.activist_id,
	fe.created_at AS action_created_date,
	a.created_at AS activist_created_at
   FROM form_entries fe
	 JOIN activists a ON a.id = fe.activist_id
	 JOIN widgets w ON w.id = fe.widget_id
	 JOIN blocks b ON b.id = w.block_id
	 JOIN mobilizations m ON m.id = b.mobilization_id;
COMMIT;
INSERT INTO public.activist_actions(action, widget_id, mobilization_id, community_id, activist_id, action_created_at, activist_created_at)
SELECT 'donations'::text AS action,
	w.id AS widget_id,
	m.id AS mobilization_id,
	m.community_id,
	fe.activist_id,
	fe.created_at AS action_created_date,
	a.created_at AS activist_created_at
   FROM donations fe
	 JOIN activists a ON a.id = fe.activist_id
	 JOIN widgets w ON w.id = fe.widget_id
	 JOIN blocks b ON b.id = w.block_id
	 JOIN mobilizations m ON m.id = b.mobilization_id;
COMMIT;
-- Create triggers to update activist_actions
-- Pressure
CREATE OR REPLACE FUNCTION copy_activist_pressures() RETURNS TRIGGER AS
$BODY$
BEGIN
    INSERT INTO
        activist_actions(action, widget_id, mobilization_id, community_id, activist_id, action_created_at, activist_created_at)
    SELECT 'activist_pressures'::text AS action,
		w.id AS widget_id,
		m.id AS mobilization_id,
		m.community_id,
		fe.activist_id,
		fe.created_at AS action_created_date,
		a.created_at AS activist_created_at
	FROM activist_pressures fe
		 JOIN activists a ON a.id = fe.activist_id
		 JOIN widgets w ON w.id = fe.widget_id
		 JOIN blocks b ON b.id = w.block_id
		 JOIN mobilizations m ON m.id = b.mobilization_id
	WHERE fe.id = new.id;
   	RETURN new;
END;
$BODY$
language plpgsql;

CREATE TRIGGER trig_copy_activist_pressures AFTER INSERT ON activist_pressures FOR EACH ROW EXECUTE PROCEDURE copy_activist_pressures();
COMMIT;
-- Donation
CREATE OR REPLACE FUNCTION copy_donations() RETURNS TRIGGER AS
$BODY$
BEGIN
    INSERT INTO
        activist_actions(action, widget_id, mobilization_id, community_id, activist_id, action_created_at, activist_created_at)
    SELECT 'donations'::text AS action,
		w.id AS widget_id,
		m.id AS mobilization_id,
		m.community_id,
		fe.activist_id,
		fe.created_at AS action_created_date,
		a.created_at AS activist_created_at
	FROM donations fe
		 JOIN activists a ON a.id = fe.activist_id
		 JOIN widgets w ON w.id = fe.widget_id
		 JOIN blocks b ON b.id = w.block_id
		 JOIN mobilizations m ON m.id = b.mobilization_id
	WHERE fe.id = new.id;
   	RETURN new;
END;
$BODY$
language plpgsql;

CREATE TRIGGER trig_copy_donations AFTER INSERT ON donations FOR EACH ROW EXECUTE PROCEDURE copy_donations();
COMMIT;
-- Form Entries
CREATE OR REPLACE FUNCTION copy_form_entries() RETURNS TRIGGER AS
$BODY$
BEGIN
    INSERT INTO
        activist_actions(action, widget_id, mobilization_id, community_id, activist_id, action_created_at, activist_created_at)
    SELECT 'form_entries'::text AS action,
		w.id AS widget_id,
		m.id AS mobilization_id,
		m.community_id,
		fe.activist_id,
		fe.created_at AS action_created_date,
		a.created_at AS activist_created_at
	FROM form_entries fe
		 JOIN activists a ON a.id = fe.activist_id
		 JOIN widgets w ON w.id = fe.widget_id
		 JOIN blocks b ON b.id = w.block_id
		 JOIN mobilizations m ON m.id = b.mobilization_id
	WHERE fe.id = new.id;
   	RETURN new;
END;
$BODY$
language plpgsql;

CREATE TRIGGER trig_copy_form_entries AFTER INSERT ON form_entries FOR EACH ROW EXECUTE PROCEDURE copy_form_entries();
COMMIT;