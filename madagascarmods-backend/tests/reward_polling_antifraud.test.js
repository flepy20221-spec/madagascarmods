'use strict';

const assert = require('assert');
const {
  rewardFraudDetection,
  shouldRunRewardPatternDetection,
} = require('../src/middleware/antiFraud');

async function run() {
  assert.strictEqual(
    shouldRunRewardPatternDetection({ body: { ad_type: 'rewarded' } }),
    false,
    'Rewarded é uma consulta SSV somente leitura e não deve pontuar padrão de crédito',
  );

  assert.strictEqual(
    shouldRunRewardPatternDetection({ body: { ad_type: 'interstitial' } }),
    true,
    'Interstitial continua sujeito à detecção de padrão',
  );

  assert.strictEqual(
    shouldRunRewardPatternDetection({ body: { ad_type: 'banner' } }),
    true,
    'Banner continua sujeito à detecção de padrão',
  );

  const req = {
    body: { ad_type: 'rewarded' },
    user: { userId: '00000000-0000-4000-8000-000000000000' },
  };
  let nextCalls = 0;

  await rewardFraudDetection(req, {}, () => {
    nextCalls += 1;
  });

  assert.strictEqual(nextCalls, 1, 'O polling rewarded deve prosseguir exatamente uma vez');
  assert.deepStrictEqual(req.fraudFlags, [], 'O polling não deve produzir flags');
  assert.strictEqual(req.fraudScore, 0, 'O polling não deve elevar o fraud_score');

  console.log('PASS: rewarded SSV polling bypasses credit-pattern scoring');
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
