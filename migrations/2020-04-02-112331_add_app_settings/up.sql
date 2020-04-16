CREATE TABLE public.app_settings
(
    id bigint NOT NULL,
    name character varying NOT NULL,
    settings json,
    version integer NOT NULL DEFAULT 1,
    community_id bigint NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT community_module_version_unique UNIQUE (name, version, community_id),
    CONSTRAINT community_id_foreign_key FOREIGN KEY (community_id)
        REFERENCES public.communities (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
)
WITH (
    OIDS = FALSE
);