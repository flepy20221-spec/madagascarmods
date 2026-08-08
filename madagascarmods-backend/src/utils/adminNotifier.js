/**
 * CashPix — Notificacoes administrativas (multi-canal)
 *
 * ============================================================================================
 * PROPOSITO
 *
 * Antes deste modulo, o unico alerta que saia do servidor era o webhook de auto-ban, embutido
 * dentro de botDetection.js e lendo BAN_WEBHOOK_URL. Toda vez que um usuario cadastrava chave
 * PIX, enviava e-mail FaucetPay ou pedia saque, ninguem era avisado: o admin precisava abrir o
 * painel e conferir na mao. Como esses tres eventos sao justamente os que exigem acao humana
 * (aprovar ou recusar), o atraso de aviso e atraso de pagamento.
 *
 * Aqui a notificacao passa a ser um servico unico, chamado pelas rotas, com quatro canais
 * possiveis ao mesmo tempo. Todos sao opcionais: sem variavel de ambiente configurada, a funcao
 * simplesmente nao faz nada e o fluxo de negocio segue identico.
 *
 * ============================================================================================
 * CANAIS SUPORTADOS
 *
 *   ADMIN_DISCORD_WEBHOOK_URL  Webhook de canal do Discord. Recebe embeds coloridos. O app do
 *                              Discord no Android entrega push nativo, e o canal serve de
 *                              historico permanente e pesquisavel.
 *
 *   ADMIN_TELEGRAM_BOT_TOKEN   Bot do Telegram + ADMIN_TELEGRAM_CHAT_ID. Entrega mais rapida e
 *   ADMIN_TELEGRAM_CHAT_ID     leve que o Discord no Android, e permite grupo com a equipe.
 *
 *   ADMIN_NTFY_TOPIC           Topico ntfy (https://ntfy.sh ou instancia propria via
 *   ADMIN_NTFY_SERVER          ADMIN_NTFY_SERVER). E a opcao com melhor comportamento de
 *                              PRIORIDADE no Android: prioridade 5 (urgent) toca som e abre
 *                              pop-over mesmo com o celular em silencioso, o que e o
 *                              comportamento desejado para pedido de saque.
 *
 *   ADMIN_GENERIC_WEBHOOK_URL  POST JSON cru, para Slack via proxy, n8n, Zapier, IFTTT,
 *                              Make ou qualquer automacao propria.
 *
 * ============================================================================================
 * REGRAS DE SEGURANCA APLICADAS
 *
 *   1. NUNCA envia dado sensivel completo. CPF, chave PIX e e-mail vao MASCARADOS, usando os
 *      mesmos helpers de src/utils/crypto.js que o painel ja usa. Um canal de Discord ou grupo
 *      de Telegram nao e ambiente confiavel para PII: mensagens ficam em cache no celular de
 *      todos os membros e no servidor da plataforma.
 *   2. Fire-and-forget com timeout. A notificacao NUNCA bloqueia a resposta HTTP ao usuario nem
 *      derruba a transacao do banco. Se o Discord estiver fora do ar, o saque continua sendo
 *      registrado normalmente.
 *   3. Chamado sempre DEPOIS do COMMIT. Notificar dentro da transacao produziria alerta de saque
 *      que acabou em ROLLBACK, ou seja, aviso de algo que nao aconteceu.
 * ============================================================================================
 */

// Timeout curto: um canal lento nao deve manter conexoes penduradas no servidor.
const NOTIFY_TIMEOUT_MS = 5000;

/**
 * Catalogo de eventos. Centralizar aqui evita que cada rota invente seu proprio titulo, cor e
 * prioridade, e permite ligar ou desligar categorias por variavel de ambiente.
 *
 * `priority` segue a escala do ntfy: 5 urgente, 4 alta, 3 padrao, 2 baixa.
 * `color` e o inteiro de cor do embed do Discord.
 */
const EVENTS = {
  PIX_KEY_SUBMITTED: {
    title: 'Nova chave PIX aguardando aprovacao',
    color: 0x00B0FF,
    priority: 4,
    tags: 'bank,hourglass',
    category: 'approvals',
  },
  PAYOUT_DESTINATION_SUBMITTED: {
    title: 'Novo e-mail de pagamento aguardando aprovacao',
    color: 0x7C4DFF,
    priority: 4,
    tags: 'email,hourglass',
    category: 'approvals',
  },
  WITHDRAWAL_REQUESTED: {
    title: 'Novo saque solicitado',
    color: 0x00C853,
    priority: 5,
    tags: 'moneybag',
    category: 'withdrawals',
  },
  USER_AUTO_BANNED: {
    title: 'Auto-ban executado',
    color: 0xD50000,
    priority: 4,
    tags: 'no_entry,robot',
    category: 'security',
  },
  IP_LIMIT_BLOCK: {
    title: 'Bloqueio por limite de contas no mesmo IP',
    color: 0xFF6D00,
    priority: 2,
    tags: 'shield',
    category: 'security',
  },
};

/**
 * Categorias habilitadas. Por padrao todas. Permite, por exemplo, receber saque e aprovacao no
 * celular sem ser inundado por alertas de bloqueio de IP:
 *   ADMIN_NOTIFY_CATEGORIES=approvals,withdrawals
 */
function categoryEnabled(category) {
  const raw = process.env.ADMIN_NOTIFY_CATEGORIES;
  if (!raw || !raw.trim()) return true;
  return raw.split(',').map(c => c.trim().toLowerCase()).filter(Boolean).includes(category);
}

/**
 * POST com timeout, sem lancar excecao para o chamador.
 */
async function safePost(url, options, channelName) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NOTIFY_TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      console.error(`[AdminNotifier] ${channelName} respondeu ${res.status}: ${body.slice(0, 200)}`);
    }
  } catch (err) {
    console.error(`[AdminNotifier] ${channelName} falhou: ${err.message}`);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Monta o corpo textual comum aos canais de texto (Telegram e ntfy).
 */
function buildTextBody(fields) {
  return Object.entries(fields)
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
}

/**
 * Escapa os caracteres reservados do HTML usado pelo Telegram em parse_mode HTML.
 * Sem isso, um nome de usuario contendo '<' ou '&' faz o Telegram recusar a mensagem inteira.
 */
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Envia uma notificacao administrativa por todos os canais configurados.
 *
 * @param {string} eventKey  Chave de EVENTS.
 * @param {object} fields    Pares rotulo -> valor, JA MASCARADOS. Aparecem na notificacao.
 * @param {object} [opts]
 * @param {string} [opts.link]   URL do painel para acao direta (vira botao/clique).
 * @param {string} [opts.footer] Texto auxiliar.
 */
function notifyAdmin(eventKey, fields = {}, opts = {}) {
  const event = EVENTS[eventKey];
  if (!event) {
    console.error(`[AdminNotifier] Evento desconhecido: ${eventKey}`);
    return;
  }
  if (!categoryEnabled(event.category)) return;

  const timestamp = new Date().toISOString();
  const textBody = buildTextBody(fields);

  // ---------------------------------------------------------------- Discord
  const discordUrl = process.env.ADMIN_DISCORD_WEBHOOK_URL || process.env.BAN_WEBHOOK_URL;
  if (discordUrl && discordUrl.includes('discord.com')) {
    const embed = {
      title: event.title,
      color: event.color,
      fields: Object.entries(fields)
        .filter(([, v]) => v !== null && v !== undefined && v !== '')
        .map(([name, value]) => ({ name, value: String(value), inline: String(value).length <= 24 })),
      timestamp,
    };
    if (opts.link) embed.url = opts.link;
    if (opts.footer) embed.footer = { text: opts.footer };

    safePost(
      discordUrl,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ embeds: [embed] }),
      },
      'Discord'
    );
  }

  // --------------------------------------------------------------- Telegram
  const tgToken = process.env.ADMIN_TELEGRAM_BOT_TOKEN;
  const tgChat = process.env.ADMIN_TELEGRAM_CHAT_ID;
  if (tgToken && tgChat) {
    let text = `<b>${escapeHtml(event.title)}</b>\n\n`;
    text += Object.entries(fields)
      .filter(([, v]) => v !== null && v !== undefined && v !== '')
      .map(([k, v]) => `<b>${escapeHtml(k)}:</b> ${escapeHtml(v)}`)
      .join('\n');
    if (opts.link) text += `\n\n<a href="${escapeHtml(opts.link)}">Abrir no painel</a>`;

    safePost(
      `https://api.telegram.org/bot${tgToken}/sendMessage`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: tgChat,
          text,
          parse_mode: 'HTML',
          disable_web_page_preview: true,
        }),
      },
      'Telegram'
    );
  }

  // ------------------------------------------------------------------- ntfy
  // Canal recomendado para o celular Android: o app ntfy respeita a prioridade enviada,
  // portanto um pedido de saque (prioridade 5) toca som mesmo no modo silencioso.
  const ntfyTopic = process.env.ADMIN_NTFY_TOPIC;
  if (ntfyTopic) {
    const ntfyServer = (process.env.ADMIN_NTFY_SERVER || 'https://ntfy.sh').replace(/\/$/, '');
    const headers = {
      'Content-Type': 'text/plain; charset=utf-8',
      // O ntfy aceita UTF-8 em header, mas nem toda etapa intermediaria preserva. O titulo e
      // mantido em ASCII no catalogo de eventos justamente para evitar '?' na notificacao.
      Title: event.title,
      Priority: String(event.priority),
      Tags: event.tags,
    };
    if (opts.link) headers.Click = opts.link;
    if (process.env.ADMIN_NTFY_TOKEN) {
      headers.Authorization = `Bearer ${process.env.ADMIN_NTFY_TOKEN}`;
    }

    safePost(
      `${ntfyServer}/${ntfyTopic}`,
      { method: 'POST', headers, body: textBody },
      'ntfy'
    );
  }

  // -------------------------------------------------------- Webhook genérico
  const genericUrl = process.env.ADMIN_GENERIC_WEBHOOK_URL;
  if (genericUrl) {
    safePost(
      genericUrl,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event: eventKey,
          title: event.title,
          category: event.category,
          fields,
          link: opts.link || null,
          timestamp,
        }),
      },
      'Webhook generico'
    );
  }
}

/**
 * URL do painel para o alvo informado, quando ADMIN_PANEL_URL estiver definida.
 * Permite tocar na notificacao do celular e cair direto na tela de aprovacao.
 */
function panelLink(path) {
  const base = process.env.ADMIN_PANEL_URL;
  if (!base) return null;
  return `${base.replace(/\/$/, '')}${path}`;
}

module.exports = { notifyAdmin, panelLink, EVENTS };
