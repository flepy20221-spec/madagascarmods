'use strict';

/**
 * FaucetPay Integration Module
 * 
 * Processa pagamentos via FaucetPay em LTC (Litecoin).
 * A cotação LTC/BRL é obtida em tempo real via CoinGecko API (gratuita).
 * 
 * Fluxo:
 * 1. Busca cotação LTC/BRL atual
 * 2. Converte o valor em R$ para LTC
 * 3. Envia o pagamento via FaucetPay API (send endpoint)
 * 4. Retorna tx_hash e saldo restante
 */

const https = require('https');

const FAUCETPAY_API_URL = process.env.FAUCETPAY_API_URL || 'https://faucetpay.io/api/v1';
const FAUCETPAY_API_KEY = process.env.FAUCETPAY_API_KEY || '';

/**
 * Faz uma requisição HTTP POST simples (sem dependência externa).
 * @param {string} url 
 * @param {object} formData - Dados a enviar como application/x-www-form-urlencoded
 * @returns {Promise<object>}
 */
function httpPost(url, formData) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const postData = new URLSearchParams(formData).toString();

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || 443,
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(new Error(`FaucetPay response parse error: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(15000, () => {
      req.destroy(new Error('Timeout na comunicacao com a FaucetPay'));
    });
    req.write(postData);
    req.end();
  });
}

/**
 * Faz uma requisição HTTP GET simples.
 * @param {string} url 
 * @returns {Promise<object>}
 */
function httpGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(new Error(`Response parse error: ${data}`));
        }
      });
    }).on('error', reject);
  });
}

/**
 * Obtém a cotação atual de LTC em BRL.
 * Tentativas: CoinGecko -> Binance LTCBRL direto -> Binance LTCUSDT*USDTBRL -> Fallback
 * @returns {Promise<number>} Preço de 1 LTC em BRL
 */
async function getLtcBrlRate() {
  // Tentativa 1: CoinGecko
  try {
    const cgData = await httpGet('https://api.coingecko.com/api/v3/simple/price?ids=litecoin&vs_currencies=brl');
    if (cgData && cgData.litecoin && cgData.litecoin.brl) {
      console.log(`[FaucetPay] Cotação CoinGecko: 1 LTC = R$ ${cgData.litecoin.brl}`);
      return cgData.litecoin.brl;
    }
  } catch (err) {
    console.warn('[FaucetPay] CoinGecko failed:', err.message);
  }

  // Tentativa 2: Binance par LTCBRL direto
  try {
    const ltcBrl = await httpGet('https://api.binance.com/api/v3/ticker/price?symbol=LTCBRL');
    if (ltcBrl && ltcBrl.price) {
      const price = parseFloat(ltcBrl.price);
      if (price > 0) {
        console.log(`[FaucetPay] Cotação Binance LTCBRL: 1 LTC = R$ ${price}`);
        return price;
      }
    }
  } catch (err) {
    console.warn('[FaucetPay] Binance LTCBRL failed:', err.message);
  }

  // Tentativa 3: Binance (LTC/USDT * USDT/BRL)
  try {
    const ltcUsdt = await httpGet('https://api.binance.com/api/v3/ticker/price?symbol=LTCUSDT');
    const usdtBrl = await httpGet('https://api.binance.com/api/v3/ticker/price?symbol=USDTBRL');
    if (ltcUsdt && ltcUsdt.price && usdtBrl && usdtBrl.price) {
      const ltcPrice = parseFloat(ltcUsdt.price) * parseFloat(usdtBrl.price);
      if (ltcPrice > 0) {
        console.log(`[FaucetPay] Cotação Binance LTCUSDT*USDTBRL: 1 LTC = R$ ${ltcPrice}`);
        return ltcPrice;
      }
    }
  } catch (err) {
    console.warn('[FaucetPay] Binance LTCUSDT*USDTBRL failed:', err.message);
  }

  // Tentativa 4: CoinCap (alternativa gratuita)
  try {
    const ccData = await httpGet('https://api.coincap.io/v2/rates/litecoin');
    if (ccData && ccData.data && ccData.data.rateUsd) {
      // Converter USD para BRL (taxa aproximada)
      const usdBrl = await httpGet('https://api.binance.com/api/v3/ticker/price?symbol=USDTBRL');
      if (usdBrl && usdBrl.price) {
        const ltcPrice = parseFloat(ccData.data.rateUsd) * parseFloat(usdBrl.price);
        if (ltcPrice > 0) {
          console.log(`[FaucetPay] Cotação CoinCap: 1 LTC = R$ ${ltcPrice}`);
          return ltcPrice;
        }
      }
    }
  } catch (err) {
    console.warn('[FaucetPay] CoinCap failed:', err.message);
  }

  // Fallback: valor aproximado de mercado (atualizado manualmente se necessário)
  // Usado APENAS se TODAS as APIs falharem
  console.warn('[FaucetPay] TODAS as APIs de cotação falharam! Usando fallback: R$ 225');
  return 225.0;
}

/**
 * Converte valor em BRL para LTC usando cotação de mercado.
 * @param {number} amountBRL - Valor em reais
 * @returns {Promise<{ltcAmount: number, exchangeRate: number}>}
 */
async function convertBrlToLtc(amountBRL) {
  const ltcBrlRate = await getLtcBrlRate();
  const ltcAmount = amountBRL / ltcBrlRate;
  
  return {
    ltcAmount: parseFloat(ltcAmount.toFixed(8)),
    exchangeRate: ltcBrlRate,
  };
}

/**
 * Verifica o saldo da conta FaucetPay.
 * @returns {Promise<{balance: number, currency: string}>}
 */
async function getBalance() {
  if (!FAUCETPAY_API_KEY) {
    throw new Error('FAUCETPAY_API_KEY não configurada');
  }

  const result = await httpPost(`${FAUCETPAY_API_URL}/balance`, {
    api_key: FAUCETPAY_API_KEY,
    currency: 'LTC',
  });

  if (result.status !== 200) {
    throw new Error(result.message || 'Erro ao consultar saldo FaucetPay');
  }

  return {
    balance: parseFloat(result.balance) / 100000000, // satoshi to LTC
    balanceSatoshi: parseInt(result.balance),
    currency: 'LTC',
  };
}

/** Interpreta o resultado logico retornado por POST /checkaddress. */
function interpretCheckAddressResult(result) {
  const status = Number(result?.status);
  const message = String(result?.message || 'Resposta inesperada da FaucetPay');
  if (status === 200 && result?.payout_user_hash) {
    return {
      verified: true,
      temporary: false,
      code: 'FAUCETPAY_ACCOUNT_VERIFIED',
      payoutUserHash: String(result.payout_user_hash),
      message,
    };
  }
  if (status === 456) {
    return {
      verified: false,
      temporary: false,
      code: 'FAUCETPAY_ACCOUNT_NOT_PAYABLE',
      message,
    };
  }
  return {
    verified: false,
    temporary: true,
    code: `FAUCETPAY_CHECK_${Number.isFinite(status) ? status : 'UNKNOWN'}`,
    message,
  };
}

/**
 * Confirma se um e-mail pertence a uma conta FaucetPay pagavel em LTC.
 * A operacao apenas consulta o cadastro: nao cria conta e nao movimenta saldo.
 */
async function checkAddress({ address, currency = 'LTC' }) {
  if (!FAUCETPAY_API_KEY) {
    return {
      verified: false,
      temporary: true,
      code: 'FAUCETPAY_KEY_MISSING',
      message: 'FAUCETPAY_API_KEY nao configurada',
    };
  }

  try {
    const result = await httpPost(`${FAUCETPAY_API_URL}/checkaddress`, {
      api_key: FAUCETPAY_API_KEY,
      address: String(address || '').trim().toLowerCase(),
      currency: String(currency || 'LTC').toUpperCase(),
    });
    return interpretCheckAddressResult(result);
  } catch (error) {
    return {
      verified: false,
      temporary: true,
      code: 'FAUCETPAY_CHECK_UNAVAILABLE',
      message: error?.message || 'Falha temporaria ao consultar a FaucetPay',
    };
  }
}

/**
 * Envia pagamento via FaucetPay.
 * 
 * @param {object} params
 * @param {string} params.to - Email FaucetPay do destinatário
 * @param {number} params.amountBRL - Valor em reais a ser pago
 * @param {string} [params.referralId] - ID de referência (withdrawal ID)
 * @returns {Promise<{success: boolean, tx_hash: string, payout_id: number, balance_remaining: number, ltcAmount: number, exchangeRate: number, message: string}>}
 */
async function sendPayment({ to, amountBRL, referralId }) {
  if (!FAUCETPAY_API_KEY) {
    throw new Error('FAUCETPAY_API_KEY não configurada. Configure a variável de ambiente.');
  }

  if (!to || !amountBRL || amountBRL <= 0) {
    throw new Error('Parâmetros inválidos: email e valor são obrigatórios');
  }

  // 1. Converter BRL para LTC com cotação de mercado
  const { ltcAmount, exchangeRate } = await convertBrlToLtc(amountBRL);
  
  // FaucetPay trabalha com satoshi (1 LTC = 100000000 satoshi)
  const amountSatoshi = Math.round(ltcAmount * 100000000);

  if (amountSatoshi <= 0) {
    throw new Error(`Valor muito baixo para enviar: R$ ${amountBRL} = ${ltcAmount} LTC`);
  }

  console.log(`[FaucetPay] Enviando pagamento: R$ ${amountBRL} = ${ltcAmount} LTC (${amountSatoshi} sat) para ${to} | Taxa: 1 LTC = R$ ${exchangeRate}`);

  // 2. Enviar pagamento via FaucetPay API
  const result = await httpPost(`${FAUCETPAY_API_URL}/send`, {
    api_key: FAUCETPAY_API_KEY,
    amount: String(amountSatoshi),
    to: to,
    currency: 'LTC',
    referral: referralId ? 'true' : 'false',
  });

  console.log('[FaucetPay] API Response:', JSON.stringify(result));

  if (result.status === 200) {
    return {
      success: true,
      tx_hash: result.payout_id ? String(result.payout_id) : null,
      payout_id: result.payout_id || null,
      payout_hash: result.payout_hash || null,
      balance_remaining: result.balance ? parseInt(result.balance) : null,
      ltcAmount,
      exchangeRate,
      message: `Pagamento de ${ltcAmount} LTC (R$ ${amountBRL.toFixed(2)}) enviado com sucesso!`,
    };
  } else {
    return {
      success: false,
      message: result.message || 'Erro desconhecido na FaucetPay',
      errorCode: result.status,
      ltcAmount,
      exchangeRate,
    };
  }
}

module.exports = {
  getLtcBrlRate,
  convertBrlToLtc,
  getBalance,
  checkAddress,
  sendPayment,
  FAUCETPAY_API_KEY,
  _test: { interpretCheckAddressResult },
};
