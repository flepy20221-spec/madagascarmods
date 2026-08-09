/**
 * Smoke test do /health com limites herdados.
 *
 * Sobe o servidor real com a configuracao problematica de producao
 * (MAX_ACCOUNTS_PER_IP_24H=8, LOGIN_IP_HARD_LIMIT=5, AUTH_RATE_LIMIT_MAX=10) e verifica
 * que o /health reporta os valores EM USO apos o piso, e nao os valores configurados.
 *
 * Uso: node scripts/smoke_health.js
 */
process.env.NODE_ENV = 'development';
process.env.JWT_SECRET = 'smoke_jwt_secret_com_mais_de_32_caracteres_ok';
process.env.JWT_REFRESH_SECRET = 'smoke_refresh_secret_com_mais_de_32_chars_ok';
process.env.APP_HMAC_SECRET = 'smoke_hmac_secret_com_mais_de_32_caracteres';
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost:5432/unused';
process.env.PORT = process.env.PORT || '3999';

// A configuracao exata suspeita em producao.
process.env.MAX_ACCOUNTS_PER_IP_24H = '8';
process.env.LOGIN_IP_HARD_LIMIT = '5';
process.env.AUTH_RATE_LIMIT_MAX = '10';

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
      const ok = l.accountsPerIp24h === 30
        && l.accountsPerIp24hConfigured === '8'
        && l.loginIpHardLimit === 100
        && l.authRequestsPer15min === 60;

      console.log(ok ? '\nRESULTADO: OK — pisos aplicados e visiveis' : '\nRESULTADO: FALHOU');
      process.exit(ok ? 0 : 1);
    });
  }).on('error', (e) => {
    console.error('erro:', e.message);
    process.exit(1);
  });
});
