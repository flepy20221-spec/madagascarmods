-- Corrige a exclusao segura de contas que ainda sao referenciadas por convites.
--
-- A FK users_referred_by_fkey impede remover um usuario que aparece como
-- referido por outra conta. A conta filha permanece intacta; apenas a
-- referencia ao usuario que sera removido vira NULL. Nenhum ledger, saldo,
-- convite da conta filha ou outra conta e apagado por esta operacao.
--
-- A protecao de saldo, merge, saques e a ordem das remocoes permanecem as
-- mesmas da migration 018.
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
  SELECT COUNT(*) INTO v_merge_target
    FROM users
   WHERE merged_into_user_id = target_user_id;
  IF v_merge_target > 0 THEN
    RAISE EXCEPTION 'Conta e destino de merge de outra conta; desvincule antes de excluir (merge_target_count=%)', v_merge_target;
  END IF;

  SELECT COALESCE(SUM(amount), 0) INTO v_previous_balance
    FROM points_ledger
   WHERE user_id = target_user_id;

  IF v_previous_balance > 1000 THEN
    RAISE EXCEPTION 'Conta protegida: saldo de % pontos excede o limite de 1000 pontos para exclusao', v_previous_balance;
  END IF;

  -- Preserva as contas que convidaram ou foram convidadas. Somente a
  -- referencia ao usuario removido e anulada para satisfazer a FK.
  UPDATE users
     SET referred_by = NULL,
         updated_at = NOW()
   WHERE referred_by = target_user_id;

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

