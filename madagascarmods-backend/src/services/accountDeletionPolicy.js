'use strict';

/**
 * Regra de proteção de saldo para exclusão de contas.
 * Contas acima do limite devem permanecer preservadas, mesmo quando inativas.
 */
const MAX_DELETABLE_BALANCE_POINTS = 1000;

function getBalancePoints(value) {
  const balance = Number(value);
  return Number.isFinite(balance) ? balance : 0;
}

function canDeleteAccount(balance) {
  return getBalancePoints(balance) <= MAX_DELETABLE_BALANCE_POINTS;
}

function deletionBlockedReason(balance) {
  const points = getBalancePoints(balance);
  if (points > MAX_DELETABLE_BALANCE_POINTS) {
    return `Conta protegida: saldo de ${points} pontos excede o limite de ${MAX_DELETABLE_BALANCE_POINTS} pontos para exclusao`;
  }
  return null;
}

module.exports = {
  MAX_DELETABLE_BALANCE_POINTS,
  getBalancePoints,
  canDeleteAccount,
  deletionBlockedReason,
};
