-- Your SQL goes here

-- add a new column on communities with default modules
alter table communities add modules jsonb default '{"mobilization":true, "settings":true}';

-- replace user_communities view on postgrapgql
CREATE OR REPLACE VIEW postgraphql.user_communities AS
 SELECT com.id,
    com.name,
    com.city,
    com.description,
    com.created_at,
    com.updated_at,
    com.mailchimp_api_key,
    com.mailchimp_list_id,
    com.mailchimp_group_id,
    com.image,
    com.recipient_id,
    com.facebook_app_id,
    com.fb_link,
    com.twitter_link,
    com.subscription_retry_interval,
    com.subscription_dead_days_interval,
    com.email_template_from,
    com.mailchimp_sync_request_at,
		com.modules
   FROM (public.communities com
     JOIN public.community_users cou ON ((cou.community_id = com.id)))
  WHERE (cou.user_id = postgraphql.current_user_id());

GRANT SELECT ON TABLE postgraphql.user_communities TO common_user;
GRANT SELECT ON TABLE postgraphql.user_communities TO admin;