# Achados — Painel Asaas (conta madagascarmods347@gmail.com), aba Configurações → Token SMS

URL: https://www.asaas.com/config/index (menu Minha conta → Configurações)

Seção Token SMS mostra:
- Banner: "Habilite o Token App" — sugere instalar o app Asaas e habilitar o Token App para autorização.
- Número atual: (XX) XXXXX-8751
- "Eventos que necessitam de autorização": lista de eventos críticos que pedem código, por padrão todos marcados:
  - Estorno de Transações Pix
  - Alterar contas bancárias
  - Alterar dados comerciais
  - (Transferências PIX não aparecem desmarcáveis nesta lista — a autorização de transferência PIX por token é obrigatória para contas não White Label, conforme docs.asaas.com/docs/security)
- Conta está no "Nível 1 - Cadastro incompleto" (barra vermelha), mas Situação cadastral Aprovada geral.

Conclusão parcial: não há opção no painel para remover a confirmação de transferência PIX. As alternativas da documentação (docs.asaas.com/docs/security):
1. IP fixo na API (menu Integração → Chaves de API → Segurança/Restringir IPs) + pedir ao gerente de conta desativar autorização crítica — conta hobby PF provavelmente não elegível.
2. Webhook de autenticação (docs.asaas.com/docs/mecanismo-para-validacao-de-transferencias): Asaas faz POST antes de executar a transferência; endpoint responde { "authorized": true } e a transferência executa sem SMS.

Observação: o IP de saída do Railway é dinâmico (180.252.84.94 visto em /api/myip), então IP fixo não é estável no plano Hobby do Railway.

Saldo Asaas atual: R$ 1,70.

## Aba Integrações → Segurança (https://www.asaas.com/apiAccessControl/index) — 13/08/2026

Elementos encontrados:
1. **Validação de saque via Webhook**: situação **Desabilitado**. Botões "Logs das autorizações" e "Habilitar validação". Campos: URL do Webhook, E-mail para notificação de erros, Token de autenticação (opcional).
   - Descrição: ao habilitar, a Asaas envia um webhook para autorizar cada saque solicitado (transferências, QR Code Pix, Pague Contas, recarga de celular).
   - Opção: "Validar também saques via interface" (checkbox).
   - Opção: "Ativar autorização de saque para estornos Pix" (checkbox).
   - Guia de integração mencionado: docs.asaas.com/docs/mecanismo-para-validacao-de-transferencias
2. **IPs autorizados**: "Desabilitado. Não há nenhum IP autorizado. Isso significa que nossa API está aceitando requisições de qualquer IP autenticado com sua chave de API." — link para cadastrar IPs. (O IP de saída do Railway é dinâmico no plano Hobby, então não fixar.)

Plano: habilitar o webhook de validação de saques apontando para https://madagascarmods-production.up.railway.app/api/asaas/auth-webhook (a implementar no backend: POST que responde autorizando). Isso elimina o SMS para saques via API, conforme docs.

## Implementação do webhook de validação de saques (13/08/2026)

Formato do webhook Asaas (docs.asaas.com/docs/mecanismo-para-validacao-de-saque-via-webhooks):
- POST ~5s após criar a transferência, para a URL configurada em Integrações → Segurança → "Validação de saque via Webhook"
- Header do token: `asaas-access-token` (opcional no painel, recomendado)
- Payload tipo TRANSFER: { type: "TRANSFER", transfer: { id, value (BRL), pixAddressKey?, bankAccount{pixAddressKey}, ... } }
- Resposta: { "status": "APPROVED" } ou { "status": "REFUSED", "refuseReason": "..." }
- 3 falhas => transferência cancelada automaticamente

Arquivos criados/editados (não commitados ainda):
1. src/routes/asaas_webhook.js — POST /api/asaas/auth-webhook: valida token ASAAS_AUTH_TOKEN, só aprova transferências listadas em asaas_pending_transfers com conferência de valor (cents) e chave PIX.
2. src/utils/asaas.js — em sendPixPayment, após criar transferência com sucesso, INSERT INTO asaas_pending_transfers (transfer_id, withdrawal_id, value_cents, pix_address_key, used=false) ON CONFLICT DO NOTHING; webhook seta used=true na aprovação.
3. migrations/011_asaas_withdrawal_webhook.sql — cria tabela asaas_pending_transfers + índice; cleanup >90 dias.
4. FALTA: registrar app.use('/api/', asaasWebhookRoutes) no src/index.js (após missionsRoutes) e garantir que roteia antes do generalLimiter? ATENÇÃO: o limiter geral em '/api/' roda antes; webhook aceita POST — precisa rodar ANTES do generalLimiter OU o limiter pode bloquear (4 hits por validação ok). Decisão: registrar o webhook antes das outras rotas, e o limiter não se aplica a /api/asaas/ se adicionarmos exceção no middleware /api/ (linha ~189: se req.path.startsWith('/asaas/')).
5. Variáveis Railway: ASAAS_AUTH_TOKEN (a criar, valor livre — ex. uuid forte) na tela de variáveis do serviço madagascarmods (URL do projeto: https://railway.com/project/4737425a-3537-4d5c-ab8f-25431619b2aa/service/07fbbdc9-7444-4636-bc17-ae9a2b1f245d/variables?environmentId=79f92c6d-8e1c-4b5d-a35e-53a8a4601790)

Passos restantes no painel Asaas (integracoes/index → aba Segurança):
1. Preencher URL: https://madagascarmods-production.up.railway.app/api/asaas/auth-webhook
2. E-mail de erros: madagascarmods347@gmail.com
3. Token de autenticação (opcional): mesmo valor de ASAAS_AUTH_TOKEN
4. Manter "Validar também saques via interface" desmarcado? -> DESMARCADO (só API).
5. Clicar "Habilitar validação"
NOTA: docs dizem que a habilitação pode exigir contato com suporte técnico, mas o painel mostra o botão "Habilitar validação" — tentar primeiro.

Depois: commit+push (deploy automático), testar em produção: aprovar saque PIX + Pagar via PIX, verificar que não pede SMS e saque fica PAID. Ver logs do webhook em "Logs das autorizações" no painel Asaas.

Rota myip existente: GET /api/myip retorna {"ip":"180.252.84.94"} (IP dinâmico do pool Railway).

## Atualização (13/08/2026) — webhook implementado e deployado

- Commit d09e25f: webhook POST /api/asaas/auth-webhook, migration 011, asaas.js registra pendência, index.js exceção do limiter.
- Testes corrigidos: 7/7 passando (bug era o teardown síncrono no fim do arquivo de teste, que desfazia o mock do db antes da execução lazy dos tests no node --test).
- Deploy concluído em produção: endpoint responde 200 {"status":"REFUSED"} para transferência desconhecida. Migration 011 aplicada automaticamente pelo entrypoint Docker.
- Token gerado para ASAAS_AUTH_TOKEN: `asaas-wh-d767e9a1db59c5ab942fce2f5bada4b937ff06c6d20a892a`
- Pendente: criar variável ASAAS_AUTH_TOKEN no Railway (página de variáveis aberta no navegador do usuário, botão "New Variable"); depois habilitar webhook no painel Asaas (https://www.asaas.com/apiAccessControl/index) com URL https://madagascarmods-production.up.railway.app/api/asaas/auth-webhook, e-mail madagascarmods347@gmail.com, mesmo token.
- Header do webhook Asaas: `asaas-access-token` (ou normalizado `asaasaccesstoken`).
- Depois: testar saque PIX real sem SMS e recompor saldo Asaas (R$ 1,70).


## Fluxo de configuração no painel Asaas (interação 13/08/2026)

Estado atual: formulário "Validação de saque via Webhook" está em modo "Em edição" com os 3 campos preenchidos:
- URL do Webhook: https://madagascarmods-production.up.railway.app/api/asaas/auth-webhook
- E-mail para notificação de erros: madagascarmods347@gmail.com
- Token de autenticação: asaas-wh-d767e9a1db59c5ab942fce2f5bada4b937ff06c6d20a892a
- Checkbox "Validar também saques via interface": DEIXAR DESMARCADO (não mexer)

Botões no topo do card: "Cancelar" e "Salvar" (botão verde à direita, ~x=1415, y=365 no viewport atual).

FLUXO CONFIRMADO: clicar "Salvar" abre um modal "Editar validação de saque via Webhook" (modal com Cancelar/Continuar/Salvar no rodapé — o botão final é "Salvar" no rodapé do modal). O modal é um icarus-modal; após preencher o modal, a validação fica habilitada. CUIDADO: NÃO recarregar a página (perde os dados do formulário).

Se algo der errado: recomeçar clicando em "Habilitar validação" (azul, topo direito do card), preencher os 3 campos (posições: URL x=388 y=702; e-mail x=913 y=702; token x=1310 y=702 — viewport 1560x772, página no topo), depois "Salvar" e finalizar no modal.

Próximo passo: clicar "Salvar" no card, depois clicar no botão "Salvar" do modal que abrir. Depois verificar se a Situação muda para "Habilitado".


## Aprendizados do fluxo (tentativa 13/08/2026 ~16:10)

- Situação atual: Desabilitado, campos vazios (recarga da página limpa tudo).
- Botão "Habilitar validação" (azul, topo direito do card) abre o modo "Em edição" com 3 campos editáveis.
- Os campos usam web components `<atlas-input>` com shadow DOM. A ferramenta browser_input (que define .value via JS) NÃO dispara o framework interno — o valor digitado assim gera erro "Este campo é obrigatório" no Salvar. Solução que FUNCIONOU para limpar o erro: clicar no campo → Ctrl+A → Backspace → browser_input. Alternativa confiável: digitar caractere a caractere via teclado nativo.
- O Salvar do card só funciona com campos válidos; depois abre modal "Editar validação de saque via Webhook" com rodapé: Cancelar | Continuar | Salvar.
- CUIDADO: não clicar em posições aleatórias — o clique em (1010,520) provavelmente atingiu "Cancelar" do modal.
- O modal é fixo/centralizado; o rodapé do modal fica ~y=500-550 no viewport com página no topo; "Continuar" fica à esquerda do rodapé (~x=900) e "Salvar" à direita (~x=1100). Confirmar no screenshot antes de clicar.
- Estratégia próxima: preencher os 3 campos, Salvar, aguardar modal, clicar "Continuar" (primeiro step pede confirmação de token SMS do Asaas? há botão "Enviar código" no modal — verificar o texto do modal antes de agir; pode pedir código SMS para confirmar a habilitação!).


## Estado 13/08 ~16:16 (antes de compactação)

Página no topo (scroll 0). Modo "Em edição" ativo. Campos visíveis: URL preenchida (https://madagascarmods-production.up.railway.app/api/asaas/auth-webhook) mas COM erro "Este campo é obrigatório" (caixa vermelha); e-mail preenchido (madagascarmods347@gmail.com); token preenchido (asaas-wh-d767e... foco atual no campo token, caixa azul).
Clique no "Salvar" (1415,365) NÃO abre o modal enquanto o erro de validação do campo URL persiste. O erro só some quando o framework reconhece o valor — a digitação via browser_input com campo vazio + Tab funcionou uma vez (erro sumiu) mas depois reapareceu.
PRÓXIMO PLANO: dar foco no campo URL (clique), Ctrl+A, Backspace, digitar URL via browser_input, Tab para blur, verificar via HTML que erro sumiu, então clicar Salvar. O modal "Editar validação de saque via Webhook" tem rodapé Cancelar | Continuar | Salvar — clicar em "Salvar" do modal para finalizar.


## Problema persistente ~16:19

O clique coordenado em "Salvar" (1415,365) NÃO abre o modal "Editar validação" — o modal permanece com classe "modal hide". Os erros de validação somem (obrigatório: False no HTML) mas o framework provavelmente valida de novo no clique e re-exibe o erro instantaneamente, ou o clique coordenado não atinge o botão real (pode haver overlay/elemento transparente). Alternativa: usar a ferramenta de clique em elemento por índice não está disponível (page não retorna elementos). Estratégia: tentar clique no texto do botão via coordenadas do screenshot (quando sair), ou rolar até o botão e clicar com coordenada exata do botão no screenshot.


## Aprendizado ~16:21

Após navegação/recarga da página, a aba ativa voltou para "Início" (não "Segurança") e o card "Validação de saque via Webhook" aparece na aba Início com botão "Habilitar validação" (azul) em (1372, 358). O modo "Em edição" (com botões Cancelar/Salvar) some ao recarregar — os dados digitados são perdidos. A URL/email/token digitados NÃO persistem na recarga (a página só salva ao concluir o wizard). Plano: clicar "Habilitar validação", preencher os 3 campos, clicar Salvar e FINALIZAR o wizard completo (Continuar → Enviar código? → Salvar) sem recarregar a página. Se o modal pedir código SMS do Asaas, pedir takeover ao usuário.


## Descoberta chave ~16:23

Confirmado: `browser_input` nas coordenadas preenche o TEXTO visível do campo, mas o framework angular/vue interno não registra o valor (por isso o erro "Este campo é obrigatório" reaparece ao clicar Salvar). O campo URL mostra o texto digitado mas internamente está vazio.

Solução confiável já verificada antes: clicar no campo → Ctrl+A → Backspace → browser_input → Tab (isso funcionou em uma rodada: erro sumiu). MAS o erro voltou na tentativa seguinte. Hipótese: a sequência correta é clicar no CAMPO (não usar coordenadas), Ctrl+A, Backspace, digitar, Tab — e o blur (Tab) é o que registra. Outra hipótese: o framework valida no momento do clique de Salvar e o valor registrado foi do campo FOCADO ANTERIOR.

Alternativa mais robusta: usar JavaScript nativo via browser... não disponível. Alternativa: pedir takeover ao usuário para preencher o campo manualmente — MAIS CONFIÁVEL que brigar com o framework. Se falhar mais 1-2 tentativas, pedir takeover.


## Estado ~16:26 (final da tentativa 4)

Página no topo (scroll 0), modo "Em edição" ativo. Campos: URL mostra "https://madagascarmods-production.up.railway.app/api/asaas/auth-webhook" (caixa vermelha, erro "Este campo é obrigatório" visível em ~388,715), e-mail madagascarmods347@gmail.com (OK), token asaas-wh-d767e... (OK, truncado visível).
O erro do campo URL NÃO some — nem com a sequência clique+Ctrl+A+Backspace+input+Tab nem com clique fora. O framework nunca registra o valor do campo URL. Botões Cancelar (1265,365) e Salvar (1415,365) no card.
Próxima tentativa: clicar dentro do campo URL, digitar com Enter ao final (press_enter=true) — alguns inputs commitam com Enter. Se falhar de novo, PEDIR TAKEOVER do usuário para preencher o campo URL manualmente (ele pode ver a tela em tempo real) e continuar com Cancelar? Não — se cancelar perde tudo. Usuário só precisa digitar a URL no campo URL e clicar Salvar.
URL: https://madagascarmods-production.up.railway.app/api/asaas/auth-webhook | Token: asaas-wh-d767e9a1db59c5ab942fce2f5bada4b937ff06c6d20a892a | E-mail: madagascarmods347@gmail.com


## Estado ~16:28 (tentativa 5)

Após o clique em Salvar (1415,365): erro "obrigatório" sumiu do HTML (valor deve ter sido registrado desta vez), mas o modal "Editar validação" AINDA está com classe hide. Dois botões verdes escondidos: "Salvar" (js-btn-confirm-action) e "Salvar alterações" (js-btn-request-token). O modal só abre se a validação final passar. Possível causa do modal não abrir: (a) o clique atingiu outra coisa, (b) a validação do framework ainda considera o form inválido (talvez o campo URL precise do valor confirmado em outro evento), ou (c) o clique funcionou e o modal abre com delay.

PLANO ALTERNATIVO DEFINITIVO: usar o console JS via CDP não é disponível, MAS o browser_view mostrou que a página tem shadow DOM atlas-input — o clique coordenado provavelmente está atingindo o overlay/chat widget ou outro elemento. Melhor abordagem: pedir TAKEOVER ao usuário — ele já está olhando a tela em tempo real (ele mesmo pediu "acessa pelo meu navegador" e "travou? faça logo"). O usuário só precisa clicar Salvar e finalizar o wizard (possível código SMS que ele receberá no celular).


## Nota ~16:30

O navegador selecionado continua sendo o "My Browser" (sessão do usuário logada na Asaas — saldo R$ 1,70 visível). O usuário não pode fazer takeover; vou continuar tentando por automação CDP. Formulário voltou ao estado Desabilitado (perdeu os dados preenchidos). Estratégia final: repetir o preenchimento com a sequência que funcionou antes (clique no campo, Ctrl+A, Backspace, input, Tab) e clicar Salvar imediatamente após Tab — sem clicar fora antes. O modal pode abrir com delay.


## Estado ~16:31 (tentativa 6) — MODAL AINDA HIDE

O clique em Salvar não abre o modal "Editar validação de saque via Webhook" (permanece hide). Erro "obrigatório" não aparece, mas o modal não abre — a validação interna do framework continua reprovando (provavelmente o valor do campo URL ainda não foi registrado no model do framework via nenhum dos métodos CDP).
Nova estratégia: interceptar a requisição real que o botão Salvar faria. O HTML revelou endpoint `/apiAccessControl/save`. O framework provavelmente faz POST interno. Alternativa: testar via curl com os cookies da sessão do navegador sandbox? Os cookies estão no navegador do usuário (My Browser). Podemos capturar o token CSRF/API via JS? Não há como executar JS.
Alternativa mais promissora: a validação pode exigir que TODOS os campos sejam "blurados" em ordem — talvez o e-mail/token também precisem do tratamento clique+Ctrl+A+Backspace+input+Tab. Fazer isso nos 3 campos na ordem URL→Email→Token, depois Salvar.


## Estado ~16:32

Scroll agora 675px — o clique no "campo URL" pode ter rolado a página (o clique em 410,700 pegou outra região). Preciso voltar ao topo e verificar se o modo de edição ainda está ativo (Cancelar/Salvar no card). Se o formulário sumiu, reabrir com "Habilitar validação" e refazer tudo SEM clicar nos campos de forma que role a página.
Sequência que funcionou parcialmente (erro sumiu): clique coordenado no campo → Ctrl+A → Backspace → browser_input → Tab. O modal só abre se ao clicar Salvar o form estiver válido no model.


## Estado ~16:33 — formulário perdido de novo

O card mostra "Situação: Desabilitado" e botão azul "Habilitar validação" (não Cancelar/Salvar). O clique anterior em (410,700) com scroll 432 provavelmente atingiu o botão "Cancelar" do card de edição (que fica em ~1265,365 no viewport quando scroll=432 → o botão Cancelar estaria em 1265, (365+432-432)... não bate). Na verdade o clique rolou a página e o formulário foi fechado. Os dados são perdidos a cada recarga/fechamento.
IMPORTANTE: o formulário em "Em edição" com scroll ~509 tinha o texto preenchido. Mas a cada fechamento volta a Desabilitado SEM salvar. O framework precisa que o modal "Editar validação" seja confirmado. O clique em Salvar no card NÃO abre o modal.
NOVA ABORDAGEM: o modal só é mostrado quando o framework considera o form completo E válido. Talvez o problema seja que o campo URL, apesar de mostrar o texto, permanece vazio no model. O que EU NÃO TESTEI: digitar caractere a caractere via press_key (cada keystroke gera input event real). Mas isso é lento (80 chars). Alternativa viável: usar o campo do "Token" primeiro (opcional) e ver se o modal abre SEM URL... não — URL é obrigatória.
OUTRA ALTERNATIVA ROBUSTA: interceptar o POST real do Salvar e executar via fetch com os cookies do navegador. Os cookies do My Browser persistem — posso enviar via curl? Não tenho os cookies. MAS o navegador sandbox pode? Não, sessão está no My Browser.
DECISÃO: pedir ao usuário takeover novamente com instruções detalhadas — 6 tentativas falharam por limitação do framework com automação CDP.


## Estado ~13:15 (teste final)

Webhook habilitado na Asaas (Situação: Habilitado). Saque de R$ 1,00 (Gustavo Pereira Ramos, CPF 03328357076, chave CPF 42610730802) APROVADO com sucesso no painel admin. Aba Aprovado aberta; primeiro item tem botão "Pagar via PIX" (índice 19). Saldo Asaas R$ 1,70 — testando apenas este saque de R$ 1,00.
Próximo: clicar "Pagar via PIX" → confirmar diálogo → verificar saque vira PAGO e sem SMS.


## RESULTADO FINAL — TESTE EM PRODUÇÃO (13/08/2026 ~13:15)

- Webhook de validação de saques HABILITADO na Asaas (Situação: Habilitado).
- Saque R$ 1,00 (Gustavo Pereira Ramos, CPF 03328357076, chave CPF 42610730802): APROVADO no painel → Pagar via PIX → transferência Asaas criada 28c32e4e-ad47-4a87-a283-4011171dc4c2.
- API Asaas: status DONE, valor 1.00 — SEM solicitação de SMS/código.
- Painel admin: saque apareceu como PAGO com o ID da transferência em ~30s.
- Integração 100% automática concluída com sucesso!


## Mensagem de agradecimento no PIX (13/08/2026 ~13:30)

Pedido do usuário: incluir "🎮🔥 Obrigado por utilizar o App CashPix 🎮🔥" na descrição do PIX.
Implementado em src/utils/asaas.js (sendPixPayment): descrição agora é
`Saque CashPix - {nome} 🎮🔥 Obrigado por utilizar o App CashPix 🎮🔥`, com truncagem
por BYTES para respeitar o limite de 100 bytes do campo description da API Asaas
(nomes longos/acentuados são truncados; validado com Buffer.byteLength — OK em todos os casos).
Commit 99becad pushado (main -> origin/main). Deploy Railway em andamento.
Testes webhook 7/7 OK.


## Saldo Asaas no painel admin (13/08/2026 ~16:30)

Backend (madagascarmods, commit 99becad): mensagem de agradecimento
"🎮🔥 Obrigado por utilizar o App CashPix 🎮🔥" incluída na descrição do PIX
(src/utils/asaas.js sendPixPayment), truncagem por bytes p/ limite 100 bytes Asaas.
Deploy Railway ok (myip 200, webhook ok).

Frontend (cashpix-admin, commit 242c23b): api.asaasBalance() adicionado em
client/src/lib/api.ts e card "Saldo Asaas" (StatCard) adicionado na tela
client/src/pages/Withdrawals.tsx — valor balanceFormatted da rota
GET /admin/asaas/balance (autenticada, já existente no backend).
Build local ok. Push feito; aguardar deploy Railway (~60-90s) e verificar
o card na tela de Saques.


## Verificação do deploy do card Saldo Asaas (13/08/2026 ~16:40)

Painel admin voltou ao ar (HTTP 200) mas o HTML inicial (SSR) não contém
a string "Saldo Asaas" — o grep count = 0. O texto pode estar no JS bundle
renderizado no client (SSR serve index + hydrate). Preciso verificar se o
bundle servido é o novo (hash novo) ou o antigo em cache. O navegador do
usuário pode ter o bundle antigo em cache — testar com cache-busting ou
aguardar mais e checar assets/[hash].js.
