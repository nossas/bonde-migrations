CREATE VIEW solidarity_mautic_form AS 
    SELECT
        data->'mautic.form_on_submit'->0->'submission'->'form'->'name' AS form_name,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'primeiro_nome' AS name,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'sobrenome_completo' AS firstname,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'email' AS email,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'whatsapp_com_ddd' AS whatsapp,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'telefone_de_atendimento_c' AS phone,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'cep' AS zip,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'cor' AS color,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'qual_sua_area_de_atuacao' AS occupation_area,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'insira_seu_numero_de_regi' AS register_number,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'sendo_voluntaria_do_mapa' AS attendance_availability,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'quantas_vezes_voce_ja_rec' AS attendance_referrals,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'atualmente_quantas_mulher' AS attendance_number,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'quanto_atendimentos_pelo' AS attendance_completed,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'todos_os_atendimentos_rea' AS guideline_expenses,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'as_voluntarias_do_mapa_do' AS guideline_secrecy,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'o_comprometimento_a_dedic' AS guideline_time_availability,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'o_mapa_do_acolhimento_ent' AS guideline_support_help,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'para_que_as_mulheres_que' AS guideline_termination_protocol,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'no_seu_primeiro_atendimen' AS study_case_1,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'para_voce_o_que_e_mais_im' AS study_case_2,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'durante_os_encontros_ana' AS study_case_3,
        data->'mautic.form_on_submit'->0->'submission'->'results'->'durante_os_atendimentos_a' AS study_case_4,
        data->'mautic.form_on_submit'->0->'timestamp' AS timestamp
    FROM
        webhooks_registry
    WHERE
        service_name = 'mautic_form';

ALTER TABLE solidarity_zd_tickets ADD COLUMN webhooks_registry_id INTEGER REFERENCES webhooks_registry(id);