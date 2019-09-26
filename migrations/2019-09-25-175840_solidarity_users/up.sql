CREATE TABLE solidarity_users (
    id SERIAL PRIMARY KEY,
    user_id BIGINT,
    url TEXT,
    name TEXT,
    email TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    time_zone TEXT,
    iana_time_zone TEXT,
    phone TEXT,
    shared_phone_number TEXT,
    photo JSONB,
    locale_id BIGINT,
    locale TEXT,
    organization_id BIGINT,
    role TEXT,
    verified BOOLEAN,
    external_id BIGINT,
    tags JSONB,
    alias TEXT,
    active BOOLEAN,
    shared BOOLEAN,
    shared_agent BOOLEAN,
    last_login_at TIMESTAMP,
    two_factor_auth_enabled BOOLEAN,
    signature TEXT,
    details TEXT,
    notes TEXT,
    role_type BIGINT,
    custom_role_id BIGINT,
    moderator BOOLEAN,
    ticket_restriction TEXT,
    only_private_comments BOOLEAN,
    restricted_agent BOOLEAN,
    suspended BOOLEAN,
    chat_only BOOLEAN,
    default_group_id BIGINT,
    report_csv BOOLEAN,
    user_fields JSONB,
    address TEXT,
    atendimentos_concludos_calculado_ BIGINT,
    atendimentos_concluidos BIGINT,
    atendimentos_em_andamento BIGINT,
    atendimentos_em_andamento_calculado_ BIGINT,
    cep TEXT,
    city TEXT,
    condition TEXT,
    cor TEXT,
    data_de_inscricao_no_bonde TIMESTAMP,
    disponibilidade_de_atendimentos TEXT,
    encaminhamentos BIGINT,
    encaminhamentos_realizados_calculado_ BIGINT,
    latitude TEXT,
    longitude TEXT,
    occupation_area TEXT,
    registration_number TEXT,
    state TEXT,
    tipo_de_acolhimento TEXT,
    ultima_atualizacao_de_dados TIMESTAMP,
    whatsapp TEXT,
    community_id INTEGER REFERENCES communities(id)
);