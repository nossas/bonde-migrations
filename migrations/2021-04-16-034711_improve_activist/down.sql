-- This file should undo anything in `up.sql`
ALTER TABLE public.activists DROP COLUMN state;
ALTER TABLE public.activists DROP COLUMN tags;