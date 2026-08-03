/**
 * CashPix — Validacao centralizada de segredos
 *
 * Motivacao (auditoria de seguranca, VULN-03 e VULN-04):
 * O codigo anterior definia os segredos assim:
 *
 *   const JWT_SECRET = process.env.JWT_SECRET || 'madagascarmods-secret-key-change-in-production';
 *   const APP_SECRET = process.env.APP_HMAC_SECRET || 'mds_app_s3cr3t_k3y_2024_pr0d';
 *
 * Esses valores de fallback estao publicados no repositorio. Se as variaveis de ambiente
 * nao estivessem configuradas no Railway, qualquer pessoa com acesso ao codigo (ou que
 * extraisse as strings do APK) poderia:
 *   - assinar um JWT com { isAdmin: true } e assumir o painel administrativo por completo
 *     (aprovar saques, definir saldo arbitrario, ler CPF e chaves PIX dos usuarios);
 *   - assinar requests com HMAC valido e burlar toda a camada antifraude.
 *
 * O aviso anterior era apenas um console.error, que nao impede o servidor de subir num
 * estado totalmente comprometido. Agora a politica e fail-closed: em producao, se um
 * segredo estiver ausente, fraco ou igual a um valor publicamente conhecido, o processo
 * NAO inicia. Falhar o deploy e infinitamente preferivel a operar com segredo publico.
 *
 * Em desenvolvimento (NODE_ENV != 'production') sao gerados segredos aleatorios em
 * memoria, para nao exigir configuracao local e para nunca reintroduzir valores fixos.
 */
const crypto = require('crypto');

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// Valores que ja estiveram no repositorio e por isso sao considerados comprometidos
// de forma permanente. Nunca podem voltar a ser aceitos.
const COMPROMISED_VALUES = new Set([
  'madagascarmods-secret-key-change-in-production',
  'madagascarmods-refresh-secret-change-in-production',
  'mds_app_s3cr3t_k3y_2024_pr0d',
  'change-me',
  'changeme',
  'secret',
  'password',
]);

const MIN_SECRET_LENGTH = 32;

const failures = [];

/**
 * Resolve um segredo obrigatorio a partir do ambiente.
 *
 * @param {string} name Nome da variavel de ambiente
 * @param {string} purpose Descricao do impacto, usada na mensagem de erro
 * @returns {string} O segredo validado (ou um aleatorio em desenvolvimento)
 */
function requireSecret(name, purpose) {
  const value = process.env[name];

  if (!value || value.trim().length === 0) {
    if (IS_PRODUCTION) {
      failures.push(`${name} nao esta definida. ${purpose}`);
      return null;
    }
    const generated = crypto.randomBytes(48).toString('hex');
    console.warn(
      `[SEGURANCA] ${name} ausente em desenvolvimento: usando segredo aleatorio efemero. ` +
      `Tokens serao invalidados a cada restart. Configure ${name} para persistir sessoes.`
    );
    return generated;
  }

  const trimmed = value.trim();

  if (COMPROMISED_VALUES.has(trimmed)) {
    const message =
      `${name} esta usando um valor publicamente conhecido (presente no repositorio). ` +
      `Gere um novo segredo. ${purpose}`;
    if (IS_PRODUCTION) {
      failures.push(message);
      return null;
    }
    console.warn(`[SEGURANCA] ${message}`);
    return trimmed;
  }

  if (trimmed.length < MIN_SECRET_LENGTH) {
    const message =
      `${name} tem apenas ${trimmed.length} caracteres; o minimo seguro e ${MIN_SECRET_LENGTH}. ${purpose}`;
    if (IS_PRODUCTION) {
      failures.push(message);
      return null;
    }
    console.warn(`[SEGURANCA] ${message}`);
    return trimmed;
  }

  return trimmed;
}

const JWT_SECRET = requireSecret(
  'JWT_SECRET',
  'Com este segredo e possivel forjar tokens de administrador e assumir o painel.'
);

const JWT_REFRESH_SECRET = requireSecret(
  'JWT_REFRESH_SECRET',
  'Com este segredo e possivel emitir tokens de acesso perpetuos para qualquer conta.'
);

const APP_HMAC_SECRET = requireSecret(
  'APP_HMAC_SECRET',
  'Com este segredo e possivel assinar requests falsas e burlar a validacao antifraude.'
);

// Fail-closed: aborta o boot em producao se qualquer segredo for invalido.
if (failures.length > 0) {
  console.error('\n=============================================================');
  console.error(' FALHA DE SEGURANCA NA INICIALIZACAO — SERVIDOR NAO INICIADO');
  console.error('=============================================================');
  failures.forEach((f, i) => console.error(` ${i + 1}. ${f}`));
  console.error('-------------------------------------------------------------');
  console.error(' Como corrigir no Railway:');
  console.error('   1. Abra o projeto > servico do backend > aba Variables');
  console.error('   2. Defina cada variavel com um valor aleatorio novo, por exemplo:');
  console.error('        node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
  console.error('   3. APP_HMAC_SECRET precisa ser identico ao valor compilado no app');
  console.error('   4. Faca o redeploy do servico');
  console.error('=============================================================\n');
  process.exit(1);
}

/**
 * Assinatura curta e nao reversivel de um segredo, para diagnostico.
 * Permite confirmar que app e servidor usam o mesmo APP_HMAC_SECRET sem expor o valor.
 */
function secretFingerprint(secret) {
  return crypto.createHash('sha256').update(secret).digest('hex').slice(0, 8);
}

module.exports = {
  JWT_SECRET,
  JWT_REFRESH_SECRET,
  APP_HMAC_SECRET,
  IS_PRODUCTION,
  secretFingerprint,
};
