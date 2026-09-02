-- Aprova as chaves PIX legadas que ja passaram pelas validacoes locais no cadastro.
-- Nao cria nem processa saques. A auditoria identifica claramente a origem sistemica.
WITH approved AS (
  UPDATE pix_accounts
     SET status = 'APPROVED',
         reviewed_at = COALESCE(reviewed_at, NOW()),
         reviewed_by = NULL,
         rejection_reason = NULL,
         updated_at = NOW()
   WHERE status = 'PENDING'
     AND is_active = true
  RETURNING id, user_id, cpf, pix_key_type, pix_key_masked
)
INSERT INTO audit_log (actor_id, actor_type, action, target_type, target_id, old_value, new_value)
SELECT user_id,
       'system',
       'PIX_ACCOUNT_AUTO_APPROVED_MIGRATION',
       'pix_account',
       id,
       '{"status":"PENDING"}'::jsonb,
       jsonb_build_object(
         'status', 'APPROVED',
         'cpf_masked', LEFT(regexp_replace(cpf, '\D', '', 'g'), 3) || '.***.***-' || RIGHT(regexp_replace(cpf, '\D', '', 'g'), 2),
         'pix_key_type', pix_key_type,
         'pix_key_masked', pix_key_masked,
         'validation', 'local'
       )
  FROM approved;
