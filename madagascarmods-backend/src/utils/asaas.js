'use strict';
/**
 * Asaas Integration Module
 *
 * Processa pagamentos PIX de saque via API da Asaas (transferencia para chave PIX externa).
 *
 * Fluxo:
 * 1. Identifica o tipo da chave PIX (CPF, CNPJ, EMAIL, TELEFONE, EVP)
 * 2. Envia a transferencia imediata via POST https://api.asaas.com/v3/transfers
 * 3. Retorna o ID da transferencia e o status
 *
 * Chaves de idempotencia na forma como no FaucetPay: uma segunda chamada com o mesmo
 * saque deve ser bloqueada pelo status PROCESSING do backend (mesma disciplina
 * anti-duplicidade das rotas /approve e /process-faucetpay).
 */
const https = require('https');

const ASAAS_API_URL = process.env.ASAAS_API_URL || 'https://api.asaas.com/v3';
const ASAAS_API_KEY = process.env.ASAAS_API_KEY || '';

// Mapeamento do tipo de chave PIX gravado no saque para o enumerado da Asaas.
// pix_key_type no schema: 'cpf', 'email' (e, futuramente, 'cnpj', 'telefone', 'evp').
const PIX_TYPE_MAP = {
  cpf: 'CPF',
  cnpj: 'CNPJ',
  email: 'EMAIL',
  telefone: 'PHONE',
  tel: 'PHONE',
  phone: 'PHONE',
  evp: 'EVP',
};

function mapPixKeyType(pixKeyType) {
  const key = String(pixKeyType || '').toLowerCase();
  const mapped = PIX_TYPE_MAP[key];
  if (!mapped) {
    throw new Error(`Tipo de chave PIX nao suportado: ${pixKeyType}`);
  }
  return mapped;
}

/**
 * Requisicao HTTP generica (GET/POST) sem dependencia externa.
 */
function httpJson(method, url, body, headers) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const postData = body ? JSON.stringify(body) : null;
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || 443,
      path: urlObj.pathname,
      method,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'User-Agent': 'CashPix-Backend/1.0',
        ...headers,
      },
    };
    if (postData) {
      options.headers['Content-Length'] = Buffer.byteLength(postData);
    }
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(data); } catch (e) { parsed = null; }
        resolve({ statusCode: res.statusCode, body: parsed, raw: data });
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => {
      req.destroy(new Error('Timeout na comunicacao com a Asaas'));
    });
    if (postData) req.write(postData);
    req.end();
  });
}

/**
 * Verifica a conexao com a Asaas (saldo da conta).
 * @returns {Promise<{success: boolean, balance?: number, balanceFormatted?: string, message?: string}>}
 */
async function getBalance() {
  if (!ASAAS_API_KEY) {
    return { success: false, message: 'ASAAS_API_KEY nao configurada' };
  }
  const res = await httpJson('GET', `${ASAAS_API_URL}/myAccount`, null, {
    access_token: ASAAS_API_KEY,
  });
  if (res.statusCode === 200 && res.body) {
    // A conta pode informar saldo disponivel em campos diferentes conforme a versao da API.
    const balance = parseFloat(
      res.body.availableBalance || res.body.balance || res.body.balanceAvailable || 0
    );
    return {
      success: true,
      balance,
      balanceFormatted: `R$ ${balance.toFixed(2)}`,
      account: res.body,
    };
  }
  const message = (res.body && res.body.errors && res.body.errors[0] && res.body.errors[0].description)
    || `Falha de autenticacao com a Asaas (HTTP ${res.statusCode})`;
  return { success: false, message };
}

/**
 * Envia uma transferencia PIX para a chave do usuario.
 *
 * @param {object} params
 * @param {string} params.pixKeyValue   - valor da chave PIX (retrato do saque)
 * @param {string} params.pixKeyType    - 'cpf' | 'email' | ... (schema pix_key_type)
 * @param {number} params.amountBRL     - valor em reais
 * @param {string} params.withdrawalId  - ID do saque (usado no description)
 * @param {string} [params.holderName]  - nome do titular (so descritivo)
 * @returns {Promise<{success: boolean, transferId?: string, status?: string, value?: number, message?: string, errorCode?: string, raw?: object}>}
 */
async function sendPixPayment({ pixKeyValue, pixKeyType, amountBRL, withdrawalId, holderName }) {
  if (!ASAAS_API_KEY) {
    return { success: false, message: 'ASAAS_API_KEY nao configurada', errorCode: 'ASAAS_KEY_MISSING' };
  }
  if (!pixKeyValue || !pixKeyType) {
    return { success: false, message: 'Dados da chave PIX ausentes no saque', errorCode: 'INVALID_PIX_DATA' };
  }
  const value = Math.round(amountBRL * 100) / 100;
  if (!(value > 0)) {
    return { success: false, message: 'Valor invalido para o saque', errorCode: 'INVALID_AMOUNT' };
  }

  let pixAddressKeyType;
  try {
    pixAddressKeyType = mapPixKeyType(pixKeyType);
  } catch (e) {
    return { success: false, message: e.message, errorCode: 'UNSUPPORTED_PIX_TYPE' };
  }

  const description = holderName
    ? `Saque CashPix - ${holderName} (saque ${withdrawalId.substring(0, 8)})`
    : `Saque CashPix (saque ${withdrawalId.substring(0, 8)})`;

  const payload = {
    pixAddressKey: String(pixKeyValue).trim(),
    pixAddressKeyType,
    value,
    description,
  };

  try {
    const res = await httpJson('POST', `${ASAAS_API_URL}/transfers`, payload, {
      access_token: ASAAS_API_KEY,
    });

    // Sucesso: Asaas retorna 200/201 com { id, status, value, ... }
    if (res.statusCode < 300 && res.body && res.body.id) {
      return {
        success: true,
        transferId: res.body.id,
        status: res.body.status,
        value,
        message: `Transferencia PIX Asaas criada: ${res.body.id}`,
        raw: res.body,
      };
    }

    // Erro da API: 4xx/5xx vem como { errors: [{ description, code? }] }
    const apiErrors = (res.body && Array.isArray(res.body.errors)) ? res.body.errors : [];
    const first = apiErrors[0] || {};
    const message = first.description || `Falha no pagamento Asaas (HTTP ${res.statusCode})`;
    const errorCode = first.code || String(res.statusCode);
    return { success: false, message, errorCode, raw: res.body };
  } catch (networkErr) {
    // Excecao de rede/timeout: nao se sabe se a Asaas processou. O chamador deve
    // tratar como incerteza (PAYMENT_UNCONFIRMED), igual ao caso FaucetPay.
    throw networkErr;
  }
}

module.exports = { getBalance, sendPixPayment };
