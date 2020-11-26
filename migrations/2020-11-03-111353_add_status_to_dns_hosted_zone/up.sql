-- Hosted Zone Status
-- created
-- propagating
-- propagated
-- certifying
-- certified

CREATE TYPE DNSHostedZoneStatus as ENUM (
  'created',
  'propagating',
  'propagated',
  'certifying',
  'certified'
);

ALTER TABLE public.dns_hosted_zones
  ADD COLUMN status DNSHostedZoneStatus DEFAULT 'created';