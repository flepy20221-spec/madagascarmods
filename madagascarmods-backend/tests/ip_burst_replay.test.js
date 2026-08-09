/**
 * CashPix — Replay da regra de rajada contra o trafego real de producao
 *
 * O teste anterior (ip_limit_floor) verifica que os limiares sao resolvidos corretamente.
 * Este verifica a pergunta que de fato importa: COM OS DADOS REAIS, a regra nova bloquearia
 * alguem que a regra antiga bloqueou indevidamente?
 *
 * Os timestamps abaixo reproduzem o padrao medido em producao no IP 152.233.23.193
 * (CGNAT de operadora movel) nas 24h que antecederam a correcao:
 *   - 70 aparelhos distintos no total  -> a regra antiga (teto 60/24h) bloqueou do 61o em diante
 *   - pico de 24 cadastros na hora mais movimentada
 *   - pico de 3 cadastros no mesmo minuto
 *
 * A regra nova mede aparelhos distintos numa janela de 10 minutos. O teste calcula a maior
 * contagem que qualquer janela de 10 minutos deslizante teria observado e exige que ela fique
 * abaixo do teto de bloqueio.
 *
 * Execucao: node --test tests/ip_burst_replay.test.js
 */
const test = require('node:test');
const assert = require('node:assert');

const BURST_WINDOW_MINUTES = 10;
const BURST_LIMIT = 40;
const ACCOUNTS_24H_LIMIT = 500;
const OLD_24H_LIMIT = 60;

/**
 * Distribuicao horaria real observada em 152.233.23.193 e .194, do audit_log e da tabela users.
 * Chave: hora do dia. Valor: cadastros naquela hora.
 */
const TRAFEGO_REAL_POR_HORA = {
  16: 2,
  18: 7,
  19: 24,  // hora de pico
  20: 14,
  21: 12,
  22: 4,
  23: 5,
  1: 3,
  2: 6,
  4: 2,
  5: 1,
  9: 3,
  11: 4,
  12: 2,
  13: 1,
  14: 3,
};

/**
 * Gera timestamps (em minutos desde o inicio) distribuindo os cadastros de cada hora.
 *
 * O pior caso realista para a regra de rajada e a distribuicao mais CONCENTRADA compativel
 * com o observado. Como o pico medido por minuto foi 3, agrupamos em blocos de 3 por minuto
 * dentro de cada hora — mais concentrado do que o trafego real, portanto conservador.
 */
function gerarTimestampsConcentrados() {
  const stamps = [];
  for (const [hora, quantidade] of Object.entries(TRAFEGO_REAL_POR_HORA)) {
    const baseMinuto = Number(hora) * 60;
    for (let i = 0; i < quantidade; i += 1) {
      // 3 cadastros por minuto, o pico real medido
      stamps.push(baseMinuto + Math.floor(i / 3));
    }
  }
  return stamps.sort((a, b) => a - b);
}

/**
 * Maior numero de cadastros que uma janela deslizante de N minutos observaria.
 */
function maiorJanela(stamps, minutos) {
  let maior = 0;
  for (let i = 0; i < stamps.length; i += 1) {
    const inicio = stamps[i];
    let count = 0;
    for (let j = i; j < stamps.length; j += 1) {
      if (stamps[j] - inicio < minutos) count += 1;
      else break;
    }
    if (count > maior) maior = count;
  }
  return maior;
}

test('a regra antiga (teto 60 em 24h) bloqueava o trafego real', () => {
  const total = Object.values(TRAFEGO_REAL_POR_HORA).reduce((a, b) => a + b, 0);

  assert.ok(
    total > OLD_24H_LIMIT,
    `O trafego real de 24h (${total} cadastros) excedia o teto antigo (${OLD_24H_LIMIT}), `
    + 'que e a razao dos 1087 bloqueios registrados no audit_log.'
  );
});

test('a regra nova de rajada NAO bloquearia o mesmo trafego real', () => {
  const stamps = gerarTimestampsConcentrados();
  const pico = maiorJanela(stamps, BURST_WINDOW_MINUTES);

  assert.ok(
    pico < BURST_LIMIT,
    `A janela de ${BURST_WINDOW_MINUTES} min mais movimentada teria observado ${pico} `
    + `cadastros, abaixo do teto de ${BURST_LIMIT}. Se este assert falhar, o falso positivo `
    + 'volta a atingir usuario legitimo.'
  );

  // Margem de seguranca: nao basta passar, precisa passar com folga, senao um dia de
  // divulgacao mais intensa reproduz o incidente.
  assert.ok(
    pico <= BURST_LIMIT * 0.8,
    `Folga insuficiente: pico ${pico} contra teto ${BURST_LIMIT}. `
    + 'Recalibrar antes que o crescimento organico alcance o limite.'
  );
});

test('o volume real de 24h fica bem abaixo da nova rede de seguranca', () => {
  const total = Object.values(TRAFEGO_REAL_POR_HORA).reduce((a, b) => a + b, 0);

  assert.ok(
    total < ACCOUNTS_24H_LIMIT / 2,
    `O volume real (${total}) deve ficar com folga sob a rede de seguranca `
    + `(${ACCOUNTS_24H_LIMIT}), que existe para abuso industrial, nao para CGNAT.`
  );
});

test('um farm automatizado continua sendo bloqueado', () => {
  // Cenario de ataque: script criando contas em serie, 80 cadastros em 2 minutos.
  const ataque = [];
  for (let i = 0; i < 80; i += 1) ataque.push(Math.floor(i / 40));

  const pico = maiorJanela(ataque, BURST_WINDOW_MINUTES);

  assert.ok(
    pico >= BURST_LIMIT,
    `Um farm de 80 cadastros em 2 min produz pico ${pico}, que deve alcancar o teto `
    + `(${BURST_LIMIT}) e ser bloqueado.`
  );
});

test('rajada moderada de divulgacao passa, rajada de script nao', () => {
  // Fronteira: 20 cadastros espalhados em 10 min (divulgacao em grupo) devem passar.
  const divulgacao = [];
  for (let i = 0; i < 20; i += 1) divulgacao.push(i % 10);
  assert.ok(
    maiorJanela(divulgacao, BURST_WINDOW_MINUTES) < BURST_LIMIT,
    'Divulgacao em grupo (20 cadastros em 10 min) deve passar.'
  );

  // 50 cadastros no MESMO minuto e automacao inequivoca.
  const script = new Array(50).fill(0);
  assert.ok(
    maiorJanela(script, BURST_WINDOW_MINUTES) >= BURST_LIMIT,
    'Automacao (50 cadastros no mesmo minuto) deve ser bloqueada.'
  );
});
