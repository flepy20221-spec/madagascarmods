/**
 * CashPix - Validacao e mascaramento de dados de pagamento
 *
 * MOTIVACAO
 * ---------
 * As funcoes `maskCpf`, `maskPixKey` e `validateCpf` viviam apenas dentro de
 * `src/routes/pix.js`, acessiveis somente pelo fluxo do aplicativo. Quando o
 * painel administrativo passou a precisar CORRIGIR uma chave de pagamento
 * cadastrada errada, havia duas opcoes ruins: duplicar as regras (com risco de
 * as duas copias divergirem e o banco terminar com mascaras inconsistentes) ou
 * importar um router HTTP so para usar seus helpers.
 *
 * Este modulo centraliza as regras. O router do aplicativo e o router do admin
 * gravam CPF, chave PIX e e-mail FaucetPay exatamente do mesmo jeito, o que e
 * essencial: `cpf_hash` e `value_hash` sao usados para garantir unicidade entre
 * contas, e uma diferenca de normalizacao (espaco, maiuscula, pontuacao) criaria
 * duplicatas invisiveis.
 */

/** Normaliza CPF para 11 digitos. */
function cleanCpf(cpf) {
  return String(cpf || '').replace(/\D/g, '');
}

/** 12345678900 -> 123.***.***-00 */
function maskCpf(cpf) {
  const clean = cleanCpf(cpf);
  if (clean.length !== 11) return '***.***.***-**';
  return `${clean.slice(0, 3)}.***.***-${clean.slice(9)}`;
}

/** ab***c@dominio.com */
function maskEmailValue(value) {
  const email = String(value || '').trim();
  if (!email.includes('@')) return '***';
  const [local, domain] = email.split('@');
  if (!local || !domain) return '***';
  if (local.length <= 2) return `${local[0]}***@${domain}`;
  return `${local.slice(0, 2)}***${local.slice(-1)}@${domain}`;
}

/** Mascara de chave PIX conforme o tipo declarado. */
function maskPixKey(type, value) {
  if (type === 'cpf') return maskCpf(value);
  return maskEmailValue(value);
}

/** Validacao completa de CPF (tamanho, repeticao e digitos verificadores). */
function validateCpf(cpf) {
  const clean = cleanCpf(cpf);
  if (clean.length !== 11) return false;
  if (/^(\d)\1{10}$/.test(clean)) return false;

  let sum = 0;
  for (let i = 0; i < 9; i++) sum += parseInt(clean[i], 10) * (10 - i);
  let remainder = (sum * 10) % 11;
  if (remainder === 10) remainder = 0;
  if (remainder !== parseInt(clean[9], 10)) return false;

  sum = 0;
  for (let i = 0; i < 10; i++) sum += parseInt(clean[i], 10) * (11 - i);
  remainder = (sum * 10) % 11;
  if (remainder === 10) remainder = 0;
  if (remainder !== parseInt(clean[10], 10)) return false;

  return true;
}

/**
 * Validacao de e-mail um pouco mais estrita que `includes('@')`.
 *
 * Um e-mail FaucetPay ou chave PIX de e-mail invalido nao gera erro imediato: ele
 * gera um saque que falha ou, pior, um pagamento enviado para o lugar errado.
 * Por isso a checagem acontece na gravacao, e nao na hora do pagamento.
 */
const EMAIL_REGEX = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;

function isValidEmail(value) {
  const email = String(value || '').trim();
  if (email.length < 5 || email.length > 255) return false;
  return EMAIL_REGEX.test(email);
}

/** Normalizacao canonica de e-mail (minusculas, sem espacos nas pontas). */
function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

/**
 * Valida um conjunto completo de dados PIX e devolve a forma normalizada.
 *
 * Retorna `{ ok: false, error, code }` em caso de dado invalido, ou
 * `{ ok: true, data: { cpf, fullName, pixKeyType, pixKeyValue, pixKeyMasked } }`.
 *
 * Centralizar o retorno desta forma evita que o router do admin repita
 * (e eventualmente relaxe) validacoes que o fluxo do aplicativo aplica.
 */
function validatePixPayload({ cpf, full_name, pix_key_type, pix_key_value }) {
  if (!cpf || !full_name || !pix_key_type || !pix_key_value) {
    return {
      ok: false,
      error: 'CPF, nome completo, tipo de chave e valor da chave sao obrigatorios',
      code: 'MISSING_FIELDS'
    };
  }

  const normalizedCpf = cleanCpf(cpf);
  if (!validateCpf(normalizedCpf)) {
    return { ok: false, error: 'CPF invalido', code: 'INVALID_CPF' };
  }

  const fullName = String(full_name).trim().replace(/\s+/g, ' ');
  if (fullName.length < 5 || fullName.length > 255) {
    return {
      ok: false,
      error: 'Nome completo deve ter entre 5 e 255 caracteres',
      code: 'INVALID_NAME'
    };
  }

  if (!['cpf', 'email'].includes(pix_key_type)) {
    return {
      ok: false,
      error: 'Tipo de chave PIX deve ser "cpf" ou "email"',
      code: 'INVALID_KEY_TYPE'
    };
  }

  let pixKeyValue;
  if (pix_key_type === 'cpf') {
    pixKeyValue = cleanCpf(pix_key_value);
    if (!validateCpf(pixKeyValue)) {
      return {
        ok: false,
        error: 'CPF informado como chave PIX e invalido',
        code: 'INVALID_PIX_KEY_CPF'
      };
    }
  } else {
    pixKeyValue = normalizeEmail(pix_key_value);
    if (!isValidEmail(pixKeyValue)) {
      return {
        ok: false,
        error: 'E-mail informado como chave PIX e invalido',
        code: 'INVALID_PIX_KEY_EMAIL'
      };
    }
  }

  return {
    ok: true,
    data: {
      cpf: normalizedCpf,
      fullName,
      pixKeyType: pix_key_type,
      pixKeyValue,
      pixKeyMasked: maskPixKey(pix_key_type, pixKeyValue)
    }
  };
}

module.exports = {
  cleanCpf,
  maskCpf,
  maskPixKey,
  maskEmailValue,
  validateCpf,
  isValidEmail,
  normalizeEmail,
  validatePixPayload
};
