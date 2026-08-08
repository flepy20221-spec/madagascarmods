/**
 * CashPix — Teste manual dos canais de notificacao administrativa
 *
 * Dispara uma notificacao de exemplo de cada tipo pelos canais configurados nas variaveis
 * de ambiente. Serve para validar webhook, token e topico ANTES de depender deles em
 * producao, sem precisar simular um saque real.
 *
 * Uso:
 *   ADMIN_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... node scripts/test-admin-notify.js
 *   ADMIN_NTFY_TOPIC=cashpix-alertas-xyz123 node scripts/test-admin-notify.js
 *
 * Uso no Railway (le as variaveis do proprio ambiente):
 *   railway run node scripts/test-admin-notify.js
 */
require('dotenv').config();
const { notifyAdmin, panelLink, EVENTS } = require('../src/utils/adminNotifier');

const CHANNELS = [
  ['Discord', process.env.ADMIN_DISCORD_WEBHOOK_URL || process.env.BAN_WEBHOOK_URL],
  ['Telegram', process.env.ADMIN_TELEGRAM_BOT_TOKEN && process.env.ADMIN_TELEGRAM_CHAT_ID],
  ['ntfy', process.env.ADMIN_NTFY_TOPIC],
  ['Webhook generico', process.env.ADMIN_GENERIC_WEBHOOK_URL],
];

console.log('=== Canais detectados ===');
let anyChannel = false;
for (const [name, value] of CHANNELS) {
  const on = Boolean(value);
  if (on) anyChannel = true;
  console.log(`  ${on ? '[ON ]' : '[off]'} ${name}`);
}
console.log(`  Painel: ${process.env.ADMIN_PANEL_URL || '(ADMIN_PANEL_URL nao definida — sem link)'}`);
console.log(`  Categorias: ${process.env.ADMIN_NOTIFY_CATEGORIES || 'todas'}`);

if (!anyChannel) {
  console.error('\nNenhum canal configurado. Defina ao menos uma variavel e rode de novo.');
  process.exit(1);
}

console.log('\n=== Disparando eventos de teste ===');

notifyAdmin('PIX_KEY_SUBMITTED', {
  'Usuario': 'device-teste@cashpix.local',
  'Nome': 'Maria',
  'CPF': '123.***.***-45',
  'Tipo de chave': 'CPF',
  'Chave': '123.***.***-45',
}, { link: panelLink('/contas-pix'), footer: 'TESTE — nao existe solicitacao real' });

notifyAdmin('PAYOUT_DESTINATION_SUBMITTED', {
  'Usuario': 'device-teste@cashpix.local',
  'Destino': 'ma***@gmail.com',
  'Tipo': 'FaucetPay',
  'Versao': '2 (troca de destino)',
}, { link: panelLink('/contas'), footer: 'TESTE — nao existe solicitacao real' });

notifyAdmin('WITHDRAWAL_REQUESTED', {
  'Metodo': 'PIX',
  'Valor': 'R$ 12,50',
  'Pontos': '25000',
  'Usuario': 'device-teste@cashpix.local',
  'Nome': 'Maria',
  'Chave': '123.***.***-45',
  'Saque ID': 'a1b2c3d4',
}, { link: panelLink('/saques'), footer: 'TESTE — nao existe saque real' });

notifyAdmin('USER_AUTO_BANNED', {
  'Usuario': 'device-teste@cashpix.local',
  'ID': 'a1b2c3d4',
  'Motivo': 'TESTE de canal',
  'Score': '10',
  'IP': '152.233.23.193',
}, { link: panelLink('/usuarios') });

// notifyAdmin e fire-and-forget: o processo precisa continuar vivo o suficiente para os
// POSTs completarem. O timeout interno do notifier e de 5s.
setTimeout(() => {
  console.log('\nConcluido. Verifique o Discord, Telegram e/ou o app ntfy no celular.');
  console.log('Eventos disponiveis no catalogo:', Object.keys(EVENTS).join(', '));
}, 6000);
