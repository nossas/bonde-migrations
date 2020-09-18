-- Drop column mobilization_id to actions tables
alter table public.form_entries drop column mobilization_id;
alter table public.activist_pressures drop column mobilization_id;
alter table public.donations drop column mobilization_id;

-- Drop table pressure_targets
drop table public.pressure_targets;