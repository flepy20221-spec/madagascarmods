-- Exclusao segura de contas (admin manual + abandono automatico)
--
-- Nao usamos ON DELETE CASCADE de proposito: o audit_log preserva o rastro
-- das acoes administrativas e o points_ledger e append-only (removemos os
-- lancamentos da conta excluida, devolvendo o saldo antigo para o registro).
--
-- Recusa contas que sao alvo de merge de outra conta (FK merged_into_user_id)
-- para nao quebrar a integridade do merge.
--
-- Ordem das remocoes respeita as FKs reais do schema:
--   1. device_account_aliases
--   2. payout_destinations   (withdrawals referencia payout_destination_id)
--   3. pix_accounts
--   4. push_tokens
--   5. withdrawals
--   6. reward_events
--   7. points_ledger
--   8. users                 (ultimo)

CREATE OR REPLACE FUNCTION delete_user_safely(target_user_id UUID)
RETURNS TABLE (previous_balance BIGINT, deleted_ledger_rows INT, deleted_withdrawals INT)
LANGUAGE plpgsql
AS $$
DECLARE
  v_previous_balance BIGINT := 0;
  v_ledger_rows INT := 0;
  v_withdrawals INT := 0;
  v_merge_target INT := 0;
BEGIN
  SELECT COUNT(*) INTO v_merge_target FROM users WHERE merged_into_user_id = target_user_id;
  IF v_merge_target > 0 THEN
    RAISE EXCEPTION 'Conta e destino de merge de outra conta; desvincule antes de excluir (merge_target_count=%)', v_merge_target;
  END IF;

  SELECT COALESCE(SUM(amount), 0) INTO v_previous_balance FROM points_ledger WHERE user_id = target_user_id;

  DELETE FROM device_account_aliases WHERE user_id = target_user_id;

  DELETE FROM payout_destinations WHERE user_id = target_user_id;

  DELETE FROM pix_accounts WHERE user_id = target_user_id;

  DELETE FROM push_tokens WHERE user_id = target_user_id;

  SELECT COUNT(*) INTO v_withdrawals FROM withdrawals WHERE user_id = target_user_id;
  DELETE FROM withdrawals WHERE user_id = target_user_id;

  DELETE FROM reward_events WHERE user_id = target_user_id;

  DELETE FROM points_ledger WHERE user_id = target_user_id;
  GET DIAGNOSTICS v_ledger_rows = ROW_COUNT;

  DELETE FROM users WHERE id = target_user_id;

  previous_balance := v_previous_balance;
  deleted_ledger_rows := v_ledger_rows;
  deleted_withdrawals := v_withdrawals;
  RETURN NEXT;
END;
$$;
