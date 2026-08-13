-- Recria delete_user_safely com a ordem correta das remocoes.
--
-- A migration 013 ja havia sido aplicada em producao com uma versao anterior
-- que removia payout_destinations ANTES de withdrawals, violando a FK
-- withdrawals_payout_destination_id_fkey em contas com saques. Como o runner
-- nao re-executa migrations ja registradas em schema_migrations, esta
-- migracao garante que a funcao correta seja aplicada mesmo nesses bancos.
--
-- Ordem valida (respeita as FKs reais do schema):
--   1. device_account_aliases
--   2. pix_accounts
--   3. push_tokens
--   4. withdrawals
--   5. payout_destinations   (depois que withdrawals foi removido)
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
  DELETE FROM pix_accounts WHERE user_id = target_user_id;
  DELETE FROM push_tokens WHERE user_id = target_user_id;
  SELECT COUNT(*) INTO v_withdrawals FROM withdrawals WHERE user_id = target_user_id;
  DELETE FROM withdrawals WHERE user_id = target_user_id;
  DELETE FROM payout_destinations WHERE user_id = target_user_id;
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
