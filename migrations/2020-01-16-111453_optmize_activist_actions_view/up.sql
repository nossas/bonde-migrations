-- Deletar view existente
DROP VIEW IF EXISTS anonymous.activist_actions;

-- Re-criar a view agora materializada
CREATE MATERIALIZED VIEW anonymous.activist_actions
 AS
 SELECT activist_actions.action_created_at,
    activist_actions.id,
    activist_actions.action,
    activist_actions.mobilization_id
   FROM activist_actions;

ALTER TABLE anonymous.activist_actions
    OWNER TO monkey_user;

COMMENT ON MATERIALIZED VIEW anonymous.activist_actions
    IS 'Public view to access data of activist actions.';

-- Criar index para ordenação e relacionamento com mobilização
CREATE INDEX activist_actions_action_created_at_order_by ON anonymous.activist_actions(action_created_at, mobilization_id, id);