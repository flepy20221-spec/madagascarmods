'use strict';
// Replica exatamente a lógica de truncagem do asaas.js para validação.
function buildDescription(holderName, withdrawalId) {
  const fixedPart = `Saque CashPix - ${holderName || 'usuario'} 🎮🔥 Obrigado por utilizar o App CashPix 🎮🔥`;
  const MAX_DESC_BYTES = 100;
  let description = fixedPart;
  if (Buffer.byteLength(description, 'utf8') > MAX_DESC_BYTES) {
    const fixedTail = ` 🎮🔥 Obrigado por utilizar o App CashPix 🎮🔥`;
    const fixedTailBytes = Buffer.byteLength(fixedTail, 'utf8');
    const prefix = 'Saque CashPix - ';
    const maxNameBytes = MAX_DESC_BYTES - fixedTailBytes - Buffer.byteLength(prefix, 'utf8');
    let name = holderName || 'usuario';
    while (Buffer.byteLength(name, 'utf8') > maxNameBytes && name.length > 0) {
      name = name.slice(0, -1);
    }
    description = `${prefix}${name}${fixedTail}`;
  }
  return description;
}

const names = [
  'Gustavo Pereira Ramos',
  'Renata Santos Da Silva',
  'M'.repeat(120),
  'João', // caracteres acentuados (2 bytes)
  '',     // sem nome
  'Ana Cláudia Pereira de Oliveira Souza', // nome longo com acento
];
let ok = true;
for (const n of names) {
  const d = buildDescription(n);
  const bytes = Buffer.byteLength(d, 'utf8');
  const pass = bytes <= 100;
  ok = ok && pass;
  console.log(`${pass ? 'OK ' : 'FAIL'} ${bytes} bytes | ${d}`);
}
process.exit(ok ? 0 : 1);
