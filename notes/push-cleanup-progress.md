# Progresso — Limpeza automática de tokens push + cobertura (sem mexer no app)

## Contexto
- Problema: apenas ~500 dos 1.779 usuários recebem push. 930 tokens inativos (53% perdidos por desinstalação/reinstalação/logout).
- Decisão do usuário: NÃO mexer no app. Implementar do lado do servidor.
- Backend: /home/ubuntu/madagascarmods/madagascarmods-backend (deploy Railway via git push, projeto overflowing-nurturing).
- Painel: /home/ubuntu/cashpix-admin (deploy Railway cashpix-admin-production).

## Implementado (backend, commits pendentes de push)
- Novo módulo: src/services/pushTokenCleanup.js
  - cleanupDeadTokens(): probe FCM (mensagem silenciosa data-only) em lotes de 500; desativa tokens com código 'messaging/registration-token-not-registered' ou 'invalid-registration-token'; NÃO desativa 'unavailable' (offline temporário); teto de 200 desativações/execução.
  - getCoverageStats(): retorna {totalUsers, reachable, unreachableInactive, neverRegistered, coveragePercent}
  - runDailyCleanupJob() + startDailyJob() às 03:30 Brasília (UTC-3).
  - Registra log em push_token_cleanup_log (cria tabela IF NOT EXISTS no primeiro run).
- src/index.js: registra startDailyJob() após app.use('/api/push', pushRoutes).
- src/routes/push.js: novas rotas admin:
  - GET /api/push/admin/coverage → {success, coverage, lastCleanup}
  - POST /api/push/admin/cleanup → executa limpeza manualmente (autenticado admin)
- Sintaxe OK em todos os arquivos; getCoverageStats testado contra produção: {"totalUsers":1781,"reachable":500,"unreachableInactive":946,"neverRegistered":351,"coveragePercent":28.07}

## Bloqueio atual (2026-08-13)
- FIREBASE_SERVICE_ACCOUNT NAO esta configurada no Railway do backend!
- POST /push/admin/cleanup em prod retornou "Firebase nao configurado".
- MAS o painel mostra envios reais com sucesso hoje (6.440 ok) — verificar como push.js roda em prod: com firebaseAdmin=null o codigo tem branch "firebase não configurado — simular envio" que conta TODOS como sucesso (successCount=tokens.length)! Ou seja, as estatísticas atuais são INFLADAS: sucesso real do FCM nunca foi medido em produção porque a variável nunca existiu.
- Solucao: pedir ao usuario a chave da conta de serviço Firebase (JSON) OU o arquivo google-services/firebase json. Sem ela, a limpeza automatica nao funciona.
- Enviar stats endpoint ainda funciona (conta tokens no banco). O cleanup e o probe so funcionam com a chave.

## Estado (2026-08-13 ~18:00)
- Variavel FIREBASE_SERVICE_ACCOUNT criada com sucesso via GraphQL (variableUpsert, input com projectId/env/serviceId) → resposta true.
- Último deploy do backend: SUCCESS 17:43:35Z (commit 2fd9b9e) — mudança de variavel NAO aciona redeploy automatico.
- Cleanup continua retornando "Firebase nao configurado" pois o processo antigo nao tem a var.
- Proximo passo: forçar restart do deploy via GraphQL (mutation restartDeployment ou redeploy). Verificar se existe mutation para restart; alternativa: fazer um commit trivial no repo para acionar o deploy automatico (ex: tocar um comentario no index.js).

## Estado (2026-08-13 ~18:05)
- Variavel FIREBASE_SERVICE_ACCOUNT criada via GraphQL (variableUpsert input: projectId=4737425a-3537-4d5c-ab8f-25431619b2aa, environmentId=79fc726a-98f7-4b85-81ea-63c136f8237c, serviceId=07fbbdc9-7444-4636-bc17-ae9a2b1f245d) → true.
- deploymentRedeploy executado no deploy e80c0fc0 → novo deploy de66f24b-b110-43c1-acac-d127f5dd15de SUCCESS às 17:49:39Z.
- MAS POST /push/admin/cleanup ainda retorna "Firebase nao configurado" em producao.
- Hipotese: variavel pode ter sido salva no environment errado OU firebaseAdmin é inicializado uma vez no require do modulo push.js (app em memoria) — mas redeploy recria processo... Ou: a chave JSON tem escape/nova linha corrompida no valor.
- Proximo: verificar se FIREBASE_SERVICE_ACCOUNT existe via serviceInstances.edges.node.variablesForServiceDeployment (check_vars2.py) e possivelmente recriar a variavel verificando o valor retornado.
- GraphQL Railway: base URL https://backboard.railway.app/graphql/v2, header Authorization: Bearer $RAILWAY_TOKEN. Mutations: variableUpsert(input:{projectId,environmentId,serviceId,name,value}), deploymentRedeploy(id:).

## Pendências
1. Commit + git push madagascarmods → deploy Railway (~90s)
2. Testar rota /api/push/admin/coverage em produção
3. Executar POST /api/push/admin/cleanup uma vez manualmente para limpar tokens mortos agora (não esperar 03:30)
4. Frontend cashpix-admin: adicionar card "Cobertura Push" na tela Notificações (/notificacoes) — cliente em /home/ubuntu/cashpix-admin/client/src/; api client em client/src/lib/api.ts (add pushCoverage() e pushCleanup()); estatísticas atuais vêm de GET /push/admin/stats; card já existe nas outras telas (StatCard pattern)
5. Deploy frontend + verificar
6. Reportar ao usuário

## Credenciais/Dados úteis
- Railway token: dad474de-a498-4b76-94a0-854f4ca65568 (GraphQL: https://backboard.railway.app/graphql/v2)
- Projeto madagascarmods: 4737425a-3537-4d5c-ab8f-25431619b2aa, serviço backend: 07fbbdc9-7444-4636-bc17-ae9a2b1f245d
- DB prod (via turntable proxy): postgresql://postgres:LtstYdekscBiEaVlNTlnBIwIPubCjvUB@turntable.proxy.rlwy.net:56225/railway
- Admin painel: flepy20221@gmail.com / CashPix@2026 (login em https://madagascarmods-production.up.railway.app/api/admin/login)
- Painel admin URL: https://cashpix-admin-production.up.railway.app
