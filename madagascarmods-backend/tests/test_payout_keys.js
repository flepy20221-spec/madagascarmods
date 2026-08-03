/**
 * Teste de ponta a ponta das rotas administrativas de correcao de chave de pagamento.
 *
 * Executa contra o backend local (porta 3010) com Postgres real, cobrindo os caminhos
 * felizes e, principalmente, as recusas: motivo ausente, CPF invalido, duplicidade entre
 * usuarios, saque em andamento e papel insuficiente.
 */
const { execSync } = require('child_process');
const crypto = require('crypto');
const { Client } = require('/home/ubuntu/work/madagascarmods-backend/node_modules/pg');

const BASE = 'http://127.0.0.1:3010/api';
const DB = 'postgresql://cashpix:cashpix@127.0.0.1:5432/cashpix_test';
const SETUP_TOKEN = 'setup_token_para_testes_locais_1234567890';

let pass = 0;
let fail = 0;

let pg;

/** Consulta direta no banco: valida o estado persistido, nao apenas a resposta HTTP. */
async function sql(query) {
  const result = await pg.query(query);
  if (!result.rows.length) return '';
  const row = result.rows[0];
  const value = row[Object.keys(row)[0]];
  return value === null || value === undefined ? '' : String(value);
}

function check(label, condition, detail = '') {
  if (condition) {
    pass += 1;
    console.log(`  OK   ${label}`);
  } else {
    fail += 1;
    console.log(`  FAIL ${label}${detail ? ` -> ${detail}` : ''}`);
  }
}

async function req(method, path, { token, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  let json = null;
  const text = await res.text();
  if (text) {
    try { json = JSON.parse(text); } catch { json = { raw: text }; }
  }
  return { status: res.status, body: json };
}

// CPFs validos gerados para teste (digitos verificadores corretos)
const CPF_A = '52998224725';
const CPF_B = '11144477735';
const CPF_C = '19100000000'; // invalido de proposito

async function main() {
  pg = new Client({ connectionString: DB });
  await pg.connect();

  console.log('\n=== PREPARACAO ===');

  // Admin super_admin via rota de setup
  const setup = await req('POST', '/admin/setup', {
    body: {
      email: 'root@teste.local',
      password: 'SenhaForte#2026',
      name: 'Root',
      setup_token: SETUP_TOKEN
    }
  });
  if (setup.status !== 201 && setup.status !== 200 && setup.status !== 403) {
    console.log('setup inesperado:', setup.status, setup.body);
  }

  const login = await req('POST', '/admin/login', {
    body: { email: 'root@teste.local', password: 'SenhaForte#2026' }
  });
  check('login super_admin', login.status === 200 && !!login.body.token, JSON.stringify(login.body));
  const superToken = login.body.token;

  // Admin com papel 'support' (nao deve poder corrigir chave)
  const supportHash = execSync(
    `cd ~/work/madagascarmods-backend && node -e "console.log(require('bcryptjs').hashSync('SenhaSupport#2026', 10))"`,
    { encoding: 'utf8' }
  ).trim();
  await sql(`INSERT INTO admin_users (id, email, password_hash, name, role, is_active)
       VALUES ('${crypto.randomUUID()}', 'support@teste.local', '${supportHash}', 'Support', 'support', true)
       ON CONFLICT (email) DO NOTHING`);
  const supportLogin = await req('POST', '/admin/login', {
    body: { email: 'support@teste.local', password: 'SenhaSupport#2026' }
  });
  check('login support', supportLogin.status === 200, JSON.stringify(supportLogin.body));
  const supportToken = supportLogin.body.token;

  // Dois usuarios do app
  const userA = crypto.randomUUID();
  const userB = crypto.randomUUID();
  // Sufixo por execucao para o script poder ser rodado varias vezes no mesmo banco.
  const run = Date.now();
  await sql(`INSERT INTO users (id, email, device_id, is_active) VALUES
       ('${userA}', 'a${run}@app.local', 'dev-a-${run}', true),
       ('${userB}', 'b${run}@app.local', 'dev-b-${run}', true)`);
  // O saldo do CashPix e derivado de points_ledger (nao existe tabela de saldo).
  await sql(`INSERT INTO points_ledger (id, user_id, amount, transaction_type, description)
       VALUES ('${crypto.randomUUID()}', '${userA}', 5000, 'ADMIN_ADJUSTMENT', 'saldo de teste'),
              ('${crypto.randomUUID()}', '${userB}', 5000, 'ADMIN_ADJUSTMENT', 'saldo de teste')`);
  check('usuarios de teste criados', await sql(`SELECT COUNT(*) FROM users WHERE id IN ('${userA}','${userB}')`) === '2');

  // ==========================================================================
  console.log('\n=== FAUCETPAY: CADASTRO PELO ADMIN ===');

  let r = await req('POST', `/admin/users/${userA}/payout-destination`, {
    token: superToken,
    body: { value: `carteira.a${run}@faucetpay.io` }
  });
  check('recusa sem motivo', r.status === 400 && r.body.code === 'REASON_REQUIRED', JSON.stringify(r.body));

  r = await req('POST', `/admin/users/${userA}/payout-destination`, {
    token: superToken,
    body: { value: 'nao-e-email', reason: 'usuario informou por chamado' }
  });
  check('recusa e-mail invalido', r.status === 400 && r.body.code === 'INVALID_EMAIL', JSON.stringify(r.body));

  r = await req('POST', `/admin/users/${userA}/payout-destination`, {
    token: supportToken,
    body: { value: `carteira.a${run}@faucetpay.io`, reason: 'usuario informou por chamado' }
  });
  check('recusa papel support (403)', r.status === 403 && r.body.code === 'INSUFFICIENT_ROLE', JSON.stringify(r.body));

  r = await req('POST', `/admin/users/${userA}/payout-destination`, {
    token: superToken,
    body: {     value: `Carteira.A${run}@FaucetPay.io  `, reason: 'usuario informou o e-mail pelo suporte' }
  });
  check('cadastro criado', r.status === 201, JSON.stringify(r.body));
  const destA = r.body.destination?.id;
  const maskedA = await sql(`SELECT value_masked FROM payout_destinations WHERE id='${destA}'`);
  check('normaliza para minusculas', maskedA.includes('@faucetpay.io'), maskedA);
  check('status APPROVED por padrao',
    await sql(`SELECT status FROM payout_destinations WHERE id='${destA}'`) === 'APPROVED');
  check('auditoria de criacao registrada',
    await sql(`SELECT COUNT(*) FROM audit_log WHERE action='PAYOUT_DESTINATION_CREATED_BY_ADMIN' AND target_id='${destA}'`) === '1');

  // ==========================================================================
  console.log('\n=== FAUCETPAY: REVELAR ===');

  r = await req('GET', `/admin/payout-destinations/${destA}/reveal`, { token: supportToken });
  check('revelar exige finance', r.status === 403, JSON.stringify(r.body));

  r = await req('GET', `/admin/payout-destinations/${destA}/reveal`, { token: superToken });
  check('revelar retorna valor em claro',
    r.status === 200 && r.body.destination.value === `carteira.a${run}@faucetpay.io`,
    JSON.stringify(r.body));
  check('revelacao auditada',
    await sql(`SELECT COUNT(*) FROM audit_log WHERE action='PAYOUT_DESTINATION_REVEALED' AND target_id='${destA}'`) === '1');

  // ==========================================================================
  console.log('\n=== FAUCETPAY: CORRECAO ===');

  r = await req('PUT', `/admin/payout-destinations/${destA}`, {
    token: superToken,
    body: { value: `carteira.a${run}@faucetpay.io`, reason: 'tentativa de repetir o mesmo valor' }
  });
  check('recusa valor identico', r.status === 400 && r.body.code === 'NO_CHANGE', JSON.stringify(r.body));

  // Destino do usuario B, para testar duplicidade
  r = await req('POST', `/admin/users/${userB}/payout-destination`, {
    token: superToken,
    body: { value: `carteira.b${run}@faucetpay.io`, reason: 'cadastro manual do usuario B' }
  });
  const destB = r.body.destination?.id;
  check('destino do usuario B criado', r.status === 201, JSON.stringify(r.body));

  r = await req('PUT', `/admin/payout-destinations/${destA}`, {
    token: superToken,
    body: { value: `carteira.b${run}@faucetpay.io`, reason: 'tentando apontar para a carteira de outro' }
  });
  check('recusa e-mail de outro usuario',
    r.status === 409 && r.body.code === 'EMAIL_ALREADY_USED', JSON.stringify(r.body));

  const versionBefore = await sql(`SELECT version FROM payout_destinations WHERE id='${destA}'`);
  r = await req('PUT', `/admin/payout-destinations/${destA}`, {
    token: superToken,
    body: { value: `carteira.a.corrigida${run}@faucetpay.io`, reason: 'usuario digitou o e-mail errado no app' }
  });
  check('correcao aplicada', r.status === 200, JSON.stringify(r.body));
  check('version incrementada',
    Number(await sql(`SELECT version FROM payout_destinations WHERE id='${destA}'`)) === Number(versionBefore) + 1);
  check('status preservado (APPROVED)',
    await sql(`SELECT status FROM payout_destinations WHERE id='${destA}'`) === 'APPROVED');

  const reveal = await req('GET', `/admin/payout-destinations/${destA}/reveal`, { token: superToken });
  check('valor cifrado atualizado corretamente',
    reveal.body.destination.value === `carteira.a.corrigida${run}@faucetpay.io`, reveal.body.destination.value);
  check('hash coerente com o novo valor',
    await sql(`SELECT value_hash FROM payout_destinations WHERE id='${destA}'`) ===
    crypto.createHash('sha256').update(`carteira.a.corrigida${run}@faucetpay.io`).digest('hex'));
  check('auditoria de edicao com valores mascarados',
    await sql(`SELECT COUNT(*) FROM audit_log WHERE action='PAYOUT_DESTINATION_EDITED' AND target_id='${destA}' AND old_value::text NOT LIKE '%carteira.a${run}@%'`) === '1');

  // Reenvio para analise
  r = await req('PUT', `/admin/payout-destinations/${destA}`, {
    token: superToken,
    body: { value: `carteira.a.v3${run}@faucetpay.io`, reason: 'reenviando para nova analise', status: 'PENDING' }
  });
  check('status PENDING quando solicitado',
    r.status === 200 && await sql(`SELECT status FROM payout_destinations WHERE id='${destA}'`) === 'PENDING',
    JSON.stringify(r.body));
  // volta para APPROVED
  await req('PUT', `/admin/payout-destinations/${destA}`, {
    token: superToken,
    body: { value: `carteira.a.final${run}@faucetpay.io`, reason: 'reaprovando apos conferencia', status: 'APPROVED' }
  });

  // ==========================================================================
  console.log('\n=== BLOQUEIO POR SAQUE EM ANDAMENTO ===');

  const wId = crypto.randomUUID();
  await sql(`INSERT INTO withdrawals (id, user_id, amount, points_debited, payment_method, status, idempotency_key)
       VALUES ('${wId}', '${userA}', 10.00, 20000, 'FAUCETPAY', 'PROCESSING', '${crypto.randomUUID()}')`);

  r = await req('PUT', `/admin/payout-destinations/${destA}`, {
    token: superToken,
    body: { value: `outra.carteira${run}@faucetpay.io`, reason: 'tentativa durante saque em andamento' }
  });
  check('bloqueia edicao com saque PROCESSING',
    r.status === 409 && r.body.code === 'WITHDRAWAL_IN_PROGRESS', JSON.stringify(r.body));

  await sql(`UPDATE withdrawals SET status='PAID' WHERE id='${wId}'`);
  r = await req('PUT', `/admin/payout-destinations/${destA}`, {
    token: superToken,
    body: { value: `liberada${run}@faucetpay.io`, reason: 'saque concluido, correcao liberada' }
  });
  check('libera apos saque concluido', r.status === 200, JSON.stringify(r.body));

  // ==========================================================================
  console.log('\n=== PIX: CADASTRO PELO ADMIN ===');

  r = await req('POST', `/admin/users/${userA}/pix-account`, {
    token: superToken,
    body: { cpf: CPF_C, full_name: 'Titular Teste A', pix_key_type: 'cpf', pix_key_value: CPF_C, reason: 'cadastro manual' }
  });
  check('recusa CPF invalido', r.status === 400 && r.body.code === 'INVALID_CPF', JSON.stringify(r.body));

  r = await req('POST', `/admin/users/${userA}/pix-account`, {
    token: superToken,
    body: { cpf: CPF_A, full_name: 'Ana', pix_key_type: 'cpf', pix_key_value: CPF_A, reason: 'cadastro manual' }
  });
  check('recusa nome curto', r.status === 400 && r.body.code === 'INVALID_NAME', JSON.stringify(r.body));

  r = await req('POST', `/admin/users/${userA}/pix-account`, {
    token: superToken,
    body: {
      cpf: '529.982.247-25',
      full_name: '  Ana   Maria  Souza ',
      pix_key_type: 'cpf',
      pix_key_value: '529.982.247-25',
      reason: 'usuario nao conseguiu cadastrar pelo app'
    }
  });
  check('conta PIX criada', r.status === 201, JSON.stringify(r.body));
  const pixA = r.body.account?.id;
  check('CPF normalizado para 11 digitos',
    await sql(`SELECT cpf FROM pix_accounts WHERE id='${pixA}'`) === CPF_A,
    await sql(`SELECT cpf FROM pix_accounts WHERE id='${pixA}'`));
  check('nome normalizado (espacos colapsados)',
    await sql(`SELECT full_name FROM pix_accounts WHERE id='${pixA}'`) === 'Ana Maria Souza',
    await sql(`SELECT full_name FROM pix_accounts WHERE id='${pixA}'`));
  check('mascara de CPF gerada',
    await sql(`SELECT pix_key_masked FROM pix_accounts WHERE id='${pixA}'`) === '529.***.***-25',
    await sql(`SELECT pix_key_masked FROM pix_accounts WHERE id='${pixA}'`));
  check('cpf_hash igual ao do fluxo do app',
    await sql(`SELECT cpf_hash FROM pix_accounts WHERE id='${pixA}'`) ===
    crypto.createHash('sha256').update(CPF_A).digest('hex'));

  // ==========================================================================
  console.log('\n=== PIX: CORRECAO ===');

  r = await req('PUT', `/admin/pix-accounts/${pixA}`, {
    token: superToken,
    body: { full_name: 'Ana Maria Souza', reason: 'mesmo nome de antes' }
  });
  check('recusa quando nada muda', r.status === 400 && r.body.code === 'NO_CHANGE', JSON.stringify(r.body));

  r = await req('PUT', `/admin/pix-accounts/${pixA}`, {
    token: superToken,
    body: { full_name: 'Ana Maria de Souza Lima', reason: 'nome divergente do titular no banco' }
  });
  check('correcao parcial (apenas nome)', r.status === 200, JSON.stringify(r.body));
  check('CPF preservado na correcao parcial',
    await sql(`SELECT cpf FROM pix_accounts WHERE id='${pixA}'`) === CPF_A);

  r = await req('PUT', `/admin/pix-accounts/${pixA}`, {
    token: superToken,
    body: { pix_key_type: 'email', pix_key_value: 'Ana.Chave@Exemplo.COM', reason: 'usuario preferiu chave e-mail' }
  });
  check('troca de tipo de chave para e-mail', r.status === 200, JSON.stringify(r.body));
  check('e-mail normalizado',
    await sql(`SELECT pix_key_value FROM pix_accounts WHERE id='${pixA}'`) === 'ana.chave@exemplo.com',
    await sql(`SELECT pix_key_value FROM pix_accounts WHERE id='${pixA}'`));
  check('mascara de e-mail gerada',
    await sql(`SELECT pix_key_masked FROM pix_accounts WHERE id='${pixA}'`) === 'an***e@exemplo.com',
    await sql(`SELECT pix_key_masked FROM pix_accounts WHERE id='${pixA}'`));

  // Duplicidade de CPF entre usuarios
  r = await req('POST', `/admin/users/${userB}/pix-account`, {
    token: superToken,
    body: { cpf: CPF_B, full_name: 'Bruno Costa Silva', pix_key_type: 'cpf', pix_key_value: CPF_B, reason: 'cadastro manual B' }
  });
  check('conta PIX do usuario B criada', r.status === 201, JSON.stringify(r.body));

  r = await req('PUT', `/admin/pix-accounts/${pixA}`, {
    token: superToken,
    body: { cpf: CPF_B, reason: 'tentando usar o CPF de outro usuario' }
  });
  check('recusa CPF de outro usuario',
    r.status === 409 && r.body.code === 'CPF_ALREADY_USED', JSON.stringify(r.body));

  r = await req('PUT', `/admin/pix-accounts/${pixA}`, {
    token: supportToken,
    body: { full_name: 'Tentativa Support Silva', reason: 'papel insuficiente' }
  });
  check('correcao PIX exige finance', r.status === 403, JSON.stringify(r.body));

  r = await req('PUT', `/admin/pix-accounts/${crypto.randomUUID()}`, {
    token: superToken,
    body: { full_name: 'Inexistente Silva', reason: 'id que nao existe' }
  });
  check('404 para conta inexistente', r.status === 404, JSON.stringify(r.body));

  check('auditoria PIX_ACCOUNT_EDITED registrada',
    Number(await sql(`SELECT COUNT(*) FROM audit_log WHERE action='PIX_ACCOUNT_EDITED' AND target_id='${pixA}'`)) >= 2);
  check('auditoria nao contem CPF em claro',
    await sql(`SELECT COUNT(*) FROM audit_log WHERE action IN ('PIX_ACCOUNT_EDITED','PIX_ACCOUNT_CREATED_BY_ADMIN') AND (old_value::text LIKE '%${CPF_A}%' OR new_value::text LIKE '%${CPF_A}%')`) === '0');

  // ==========================================================================
  console.log('\n=== COMPATIBILIDADE: FLUXO DO APP APOS REFATORACAO ===');

  const pixStatus = await sql(`SELECT status FROM pix_accounts WHERE id='${pixA}'`);
  check('conta corrigida segue ativa e utilizavel',
    await sql(`SELECT is_active FROM pix_accounts WHERE id='${pixA}'`) === 't' && pixStatus === 'APPROVED',
    `is_active/status = ${pixStatus}`);

  console.log(`\n=== RESULTADO: ${pass} passaram, ${fail} falharam ===\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch(err => {
  console.error('ERRO FATAL:', err);
  process.exit(1);
});
