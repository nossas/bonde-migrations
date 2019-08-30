-- This file should undo anything in `up.sql`
DROP TRIGGER chatbots_settings_update_at ON chatbot_settings;

DROP TABLE public.chatbot_settings;

DROP SEQUENCE public.chatbot_settings_id_seq;

DROP TRIGGER chatbots_campaigns_update_at ON chatbot_campaigns;

DROP TABLE public.chatbot_campaigns;

DROP SEQUENCE public.chatbot_campaigns_id_seq;

DROP TRIGGER chatbots_update_at ON chatbots;

DROP TABLE public.chatbots;

DROP SEQUENCE public.chatbots_id_seq;

DROP FUNCTION updated_at_column;