'use strict';

/**
 * Validacao estatistica do sorteio ponderado de pontos.
 * Executar com: node test/pointsRandom.test.js
 */

const assert = require('assert');
const {
  POINT_VALUES,
  drawRewardPoints,
  getRewardDistribution,
} = require('../src/utils/pointsRandom');

const N = 500000;

// --- 1. Todos os valores sorteados pertencem a grade -------------------------
const counts = new Map();
for (let i = 0; i < N; i += 1) {
  const { points } = drawRewardPoints();
  assert.ok(
    POINT_VALUES.includes(points),
    `valor sorteado fora da grade: ${points}`
  );
  counts.set(points, (counts.get(points) || 0) + 1);
}

// --- 2. Distribuicao teorica soma 1 -----------------------------------------
const dist = getRewardDistribution();
const total = dist.reduce((s, d) => s + d.probability, 0);
assert.ok(Math.abs(total - 1) < 1e-9, `distribuicao nao soma 1: ${total}`);

// --- 3. Frequencia empirica converge para a teorica -------------------------
console.log('Valor | Teorico     | Empirico    | Desvio');
console.log('------|-------------|-------------|--------');
for (const { value, probability } of dist) {
  const empirical = (counts.get(value) || 0) / N;
  const deviation = Math.abs(empirical - probability);
  const tolerance = Math.max(0.002, probability * 0.15);
  console.log(
    `${String(value).padStart(5)} | ${(probability * 100).toFixed(4).padStart(10)}% | ` +
    `${(empirical * 100).toFixed(4).padStart(10)}% | ${(deviation * 100).toFixed(4)}%`
  );
  assert.ok(
    deviation < tolerance,
    `desvio excessivo para ${value}: ${deviation} (tolerancia ${tolerance})`
  );
}

// --- 4. Valores altos sao raros ---------------------------------------------
const highValues = [300, 400];
const highShare = highValues.reduce((s, v) => s + (counts.get(v) || 0), 0) / N;
assert.ok(highShare < 0.01, `valores altos frequentes demais: ${highShare}`);

const lowValues = [1, 2, 4];
const lowShare = lowValues.reduce((s, v) => s + (counts.get(v) || 0), 0) / N;
assert.ok(lowShare > 0.6, `valores baixos raros demais: ${lowShare}`);

// --- 5. Multiplicador ---------------------------------------------------------
const scaled = drawRewardPoints({ multiplier: 10 });
assert.ok(scaled.points >= 10, 'multiplicador nao aplicado');

console.log('\nResumo:');
console.log(`  faixa 1-4    : ${(lowShare * 100).toFixed(2)}% (esperado ~70%)`);
console.log(`  faixa 300-400: ${(highShare * 100).toFixed(4)}% (esperado ~0.2%)`);
console.log('\nTodos os testes passaram.');
