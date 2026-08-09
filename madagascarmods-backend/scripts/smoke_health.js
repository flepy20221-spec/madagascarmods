/**
 * Smoke test do /health com limites herdados e trava de rajada.
 *
 * Sobe o servidor real com a configuracao mais hostil possivel — valores baixos herdados em
 * TODAS as variaveis de limite, incluindo a de rajada — e verifica que o /health reporta os
 * valores EM USO apos os pisos, nao os configurados.
 *
 * Verifica end-to-end aquilo que os testes unitarios so cobrem isoladamente: que o processo
 * real, com Express montado e middlewares carregados, opera com os limites corretos.
 *
 * Uso: node scripts/smoke_health.js
 */
process.env.NODE_ENV = 'development';
process.env.JWT_SECRET = 'smoke_jwt_secret_com_mais_de_32_caracteres_ok';
process.env.JWT_REFRESH_SECRET = 'smoke_refresh_secret_com_mais_de_32_chars_ok';
process.env.APP_HMAC_SECRET = 'smoke_hmac_secret_com_mais_de_32_caracteres';
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost:5432/unused';
process.env.PORT = process.env.PORT || '3999';

// A configuracao exata suspeita em producao, mais um valor hostil na trava de rajada.
process.env.MAX_ACCOUNTS_PER_IP_24H = '8';
process.env.LOGIN_IP_HARD_LIMIT = '5';
process.env.AUTH_RATE_LIMIT_MAX = '10';
process.env.IP_BURST_LIMIT = '2';

const http = require('http');
const app = require('../src/index.js');

const server = app.listen(0, async () => {
  const port = server.address().port;

  http.get(`http://127.0.0.1:${port}/health`, (res) => {
    let data = '';
    res.on('data', (c) => { data += c; });
    res.on('end', () => {
      const body = JSON.parse(data);
      console.log('HTTP', res.statusCode);
      console.log('version:', body.version);
      console.log('networkLimits:', JSON.stringify(body.networkLimits, null, 2));

      const l = body.networkLimits || {};

      // Cada verificacao nomeada, para que a falha aponte o limite errado em vez de um
      // booleano opaco.
      const checks = [
        ['rajada: piso aplicado', l.ipBurstLimit === 25],
        ['rajada: configurado visivel', l.ipBurstConfigured === '2'],
        ['rajada: janela de 10 min', l.ipBurstWindowMinutes === 10],
        ['rajada: observacao abaixo do bloqueio', l.ipBurstObserveLimit < l.ipBurstLimit],
        ['24h: piso aplicado', l.accountsPerIp24h === 200],
        ['24h: configurado visivel', l.accountsPerIp24hConfigured === '8'],
        ['login: piso aplicado', l.loginIpHardLimit === 100],
        ['rate limit: piso aplicado', l.authRequestsPer15min === 60],
      ];

      let ok = true;
      for (const [nome, passou] of checks) {
        console.log(`  ${passou ? 'ok  ' : 'FALHA'} ${nome}`);
        if (!passou) ok = false;
      }

      console.log(ok ? '\nRESULTADO: OK — pisos aplicados e visiveis' : '\nRESULTADO: FALHOU');
      process.exit(ok ? 0 : 1);
    });
  }).on('error', (e) => {
    console.error('erro:', e.message);
    process.exit(1);
  });
});
