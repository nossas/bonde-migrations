-- Drop related objects on table
DROP TABLE public.activist_actions;
DROP SEQUENCE public.activist_actions_id_seq;

-- Re-create like view
-- View: public.activist_actions

-- DROP VIEW public.activist_actions;

CREATE OR REPLACE VIEW public.activist_actions
 AS
 SELECT t.action,
    t.widget_id,
    t.mobilization_id,
    t.community_id,
    t.activist_id,
    t.action_created_date,
    t.activist_created_at,
    t.activist_email
   FROM ( SELECT 'form_entries'::text AS action,
            w.id AS widget_id,
            m.id AS mobilization_id,
            m.community_id,
            fe.activist_id,
            fe.created_at AS action_created_date,
            a.created_at AS activist_created_at,
            a.email AS activist_email
           FROM form_entries fe
             JOIN activists a ON a.id = fe.activist_id
             JOIN widgets w ON w.id = fe.widget_id
             JOIN blocks b ON b.id = w.block_id
             JOIN mobilizations m ON m.id = b.mobilization_id
        UNION ALL
         SELECT 'activist_pressures'::text AS action,
            w.id AS widget_id,
            m.id AS mobilization_id,
            m.community_id,
            ap.activist_id,
            ap.created_at AS action_created_date,
            a.created_at AS activist_created_at,
            a.email AS activist_email
           FROM activist_pressures ap
             JOIN activists a ON a.id = ap.activist_id
             JOIN widgets w ON w.id = ap.widget_id
             JOIN blocks b ON b.id = w.block_id
             JOIN mobilizations m ON m.id = b.mobilization_id
        UNION ALL
         SELECT 'donations'::text AS action,
            w.id AS widget_id,
            m.id AS mobilization_id,
            m.community_id,
            d.activist_id,
            d.created_at AS action_created_date,
            a.created_at AS activist_created_at,
            a.email AS activist_email
           FROM donations d
             JOIN activists a ON a.id = d.activist_id
             JOIN widgets w ON w.id = d.widget_id
             JOIN blocks b ON b.id = w.block_id
             JOIN mobilizations m ON m.id = b.mobilization_id) t;

ALTER TABLE public.activist_actions
    OWNER TO monkey_user;

GRANT SELECT ON TABLE public.activist_actions TO admin;
GRANT SELECT ON TABLE public.activist_actions TO common_user;
GRANT ALL ON TABLE public.activist_actions TO monkey_user;
GRANT SELECT ON TABLE public.activist_actions TO postgraphql;

-- Triggers
DROP FUNCTION copy_activist_pressures;
DROP TRIGGER trig_copy_activist_pressures ON activist_pressures;

DROP FUNCTION copy_donations;
DROP TRIGGER trig_copy_donations ON donations;

DROP FUNCTION copy_form_entries;
DROP TRIGGER trig_copy_form_entries ON form_entries;