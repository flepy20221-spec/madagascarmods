'use strict';

/**
 * Sorteio de pontos com probabilidade ponderada.
 *
 * Esta lógica reproduz fielmente o comportamento do APK v1.3.0
 * (`_getRandomPoints()` em `reward_screen.dart`), onde o usuário tem
 * chance decrescente de obter as pontuações mais altas.
 *
 * Distribuição (roll = random * 100):
 *   roll <  70.0  -> 70.0%  : [1, 1, 1, 2, 2, 4]
 *   roll <  90.0  -> 20.0%  : [8, 8, 12, 16]
 *   roll <  98.0  ->  8.0%  : [20, 30, 40, 60]
 *   roll <  99.8  ->  1.8%  : [80, 100, 200]
 *   senão         ->  0.2%  : [300, 400]
 *
 * Valores exibidos na grade da tela principal:
 *   [1, 2, 4, 8, 12, 16, 20, 30, 40, 60, 80, 100, 200, 300, 400]
 */

const crypto = require('crypto');

/** Grade completa de valores possíveis exibida na tela principal. */
const POINT_VALUES = [1, 2, 4, 8, 12, 16, 20, 30, 40, 60, 80, 100, 200, 300, 400];

/**
 * Faixas de raridade em cascata. `threshold` é o limite superior (exclusivo)
 * do `roll` (0-100) para a faixa. As faixas devem estar em ordem crescente.
 */
const REWARD_TIERS = [
  { threshold: 70.0, options: [1, 1, 1, 2, 2, 4] },
  { threshold: 90.0, options: [8, 8, 12, 16] },
  { threshold: 98.0, options: [20, 30, 40, 60] },
  { threshold: 99.8, options: [80, 100, 200] },
  { threshold: 100.0, options: [300, 400] },
];

/**
 * Float criptograficamente seguro em [0, 1).
 * Usa 6 bytes (48 bits) de entropia, o suficiente para a precisão exigida.
 * @returns {number}
 */
function secureRandomFloat() {
  const buf = crypto.randomBytes(6);
  let value = 0;
  for (let i = 0; i < 6; i += 1) {
    value = value * 256 + buf[i];
  }
  return value / 2 ** 48;
}

/**
 * Inteiro criptograficamente seguro em [0, max), sem viés de módulo.
 * @param {number} max limite superior exclusivo (> 0)
 * @returns {number}
 */
function secureRandomInt(max) {
  if (!Number.isInteger(max) || max <= 0) {
    throw new RangeError('max deve ser um inteiro positivo');
  }
  const limit = Math.floor(2 ** 32 / max) * max;
  let value;
  do {
    value = crypto.randomBytes(4).readUInt32BE(0);
  } while (value >= limit);
  return value % max;
}

/**
 * Sorteia a quantidade de pontos da recompensa aplicando a distribuição
 * ponderada da v1.3.0.
 *
 * @param {object} [opts]
 * @param {number} [opts.multiplier=1] multiplicador aplicado ao valor sorteado
 * @returns {{ points: number, roll: number, tier: number }}
 */
function drawRewardPoints(opts = {}) {
  const multiplier = Number.isFinite(opts.multiplier) && opts.multiplier > 0
    ? opts.multiplier
    : 1;

  const roll = secureRandomFloat() * 100;

  for (let tier = 0; tier < REWARD_TIERS.length; tier += 1) {
    const { threshold, options } = REWARD_TIERS[tier];
    if (roll < threshold || tier === REWARD_TIERS.length - 1) {
      const base = options[secureRandomInt(options.length)];
      return {
        points: Math.max(1, Math.round(base * multiplier)),
        roll,
        tier: tier + 1,
      };
    }
  }

  // Inalcançável, mantido por segurança.
  return { points: 1, roll, tier: REWARD_TIERS.length };
}

/**
 * Distribuição teórica de probabilidade por valor de ponto.
 * Útil para exposição em `/api/config/app` e para testes.
 * @returns {Array<{ value: number, probability: number }>}
 */
function getRewardDistribution() {
  const acc = new Map();
  let previous = 0;

  for (const { threshold, options } of REWARD_TIERS) {
    const tierProbability = (threshold - previous) / 100;
    previous = threshold;
    for (const value of options) {
      const share = tierProbability / options.length;
      acc.set(value, (acc.get(value) || 0) + share);
    }
  }

  return [...acc.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([value, probability]) => ({ value, probability }));
}

module.exports = {
  POINT_VALUES,
  REWARD_TIERS,
  drawRewardPoints,
  getRewardDistribution,
  secureRandomFloat,
  secureRandomInt,
};
