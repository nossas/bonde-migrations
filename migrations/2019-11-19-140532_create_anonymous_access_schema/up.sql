-- SCHEMA: anonymous
-- DROP SCHEMA anonymous;

CREATE SCHEMA anonymous;

-- View: anonymous.mobilizations
-- DROP VIEW anonymous.mobilizations;

CREATE OR REPLACE VIEW anonymous.mobilizations AS
	SELECT id, name, created_at, user_id, color_scheme, google_analytics_code, goal, facebook_share_title, facebook_share_description, header_font, body_font, facebook_share_image, slug, custom_domain, twitter_share_text, community_id, favicon, traefik_host_rule, traefik_backend_address
	FROM public.mobilizations
	WHERE deleted_at IS NULL
	AND status = 'active';

COMMENT ON VIEW anonymous.mobilizations IS 'Public view to access data of mobilizations.';

-- View: anonymous.communities
-- DROP VIEW anonymous.communities;

CREATE OR REPLACE VIEW anonymous.communities AS
	SELECT id, name, city, created_at, image, description, fb_link, twitter_link, email_template_from
	FROM public.communities;

COMMENT ON VIEW anonymous.communities IS 'Public view to access data of communities.';

-- View: anonymous.activist_actions
-- DROP VIEW anonymous.activist_actions;

CREATE OR REPLACE VIEW anonymous.activist_actions AS
	SELECT action_created_at, id, action, mobilization_id
	FROM public.activist_actions;

COMMENT ON VIEW anonymous.activist_actions IS 'Public view to access data of activist actions.';