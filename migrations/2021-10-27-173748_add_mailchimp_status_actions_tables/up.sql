ALTER TABLE public.activist_pressures ADD COLUMN mailchimp_status VARCHAR(20) NULL;
ALTER TABLE public.donations ADD COLUMN mailchimp_status VARCHAR(20) NULL;
ALTER TABLE public.form_entries ADD COLUMN mailchimp_status VARCHAR(20) NULL;