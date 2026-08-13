# Tarefa atual: Relatório de saques + Exclusão de contas + Contas abandonadas (20 dias)

## Estado (fase 3 em andamento)

### 1. Relatório de saques (CONCLUÍDO E TESTADO EM PRODUÇÃO)
- Backend: GET /api/admin/withdrawals/report e GET /api/admin/withdrawals/report/csv (admin.js, commits c998d51, b5be551, 12232ca)
- Parâmetros: from, to (YYYY-MM-DD, default últimos 30 dias), status (csv), method (csv)
- Retorna: period, totals (count, amount), byMethod, byStatus, byDay
- CSV: separado por ; com BOM UTF-8, nome saques-{from}-a-{to}.csv
- Testado em produção OK: 60 saques, R$108.07 (01-13/08/2026), pix R$70.20, faucetpay R$37.87
- PENDENTE: UI no frontend (tela Relatório de Saques com filtros + gráfico + botão exportar CSV)

### 2. Exclusão manual de contas (backend PRONTO, falta UI)
- Migration 013: migrations/013_account_deletion.sql — função SQL delete_user_safely(user_id)
  - Remove na ordem: device_account_aliases, payout_destinations, pix_accounts, push_tokens, withdrawals, reward_events, points_ledger, users
  - Recusa se merged_into_user_id aponta para ela
  - Devolve previous_balance, deleted_ledger_rows, deleted_withdrawals
- Rota admin.js: DELETE /api/admin/users/:id (body { reason } min 5 chars) → audit_log ACCOUNT_DELETED
- Rota admin.js: GET /api/admin/users/abandoned?observationDays=15&exclusionDays=20 → lista observação + pendingExclusion

### 3. Exclusão automática de abandonadas (backend pronto)
- Serviço: src/services/abandonedAccounts.js
  - run(): elegíveis = sem login >= 20 dias (ou nunca logou, criada >= 20d), sem saque PAID/PROCESSING, não banida, não alvo de merge, máx 50/run
  - Loga audit ACCOUNT_DELETED_AUTO com detalhes
  - scheduleJob(): roda todo dia 07:00 UTC (04:00 BRT)
- FALTA: registrar no index.js (require + scheduleJob()) — editar /home/ubuntu/madagascarmods/madagascarmods-backend/src/index.js perto do job do pushTokenCleanup (ver como pushTokenCleanup.scheduleJob foi chamado)
- FALTA: commit+push backend, deploy, testar em produção

### 4. Frontend (cashpix-admin) — PENDENTE
- api.ts: adicionar deleteAccount(id, reason), abandonedUsers(), withdrawalsReport(params), CSV via fetch direto (api.get com blob)
- AppUsers.tsx: botão "Excluir" por usuário (ConfirmDialog, motivo), e card/linha de contas em observação
- Nova página ou seção "Relatório de Saques" com filtros de data, cards totais, tabela byDay (gráfico simples com barras CSS ou recharts? usar barras CSS/divs para não adicionar dependência), botão Exportar CSV
- Adicionar rota no App.tsx/router se nova página
- Depois: tsc --noEmit, commit, push

### Deploy/teste
- Backend: https://madagascarmods-production.up.railway.app (Railway auto-deploy via GitHub push)
- Admin: https://cashpix-admin-production.up.railway.app
- Login admin teste: curl POST /api/admin/login {email:flepy20221@gmail.com, password:CashPix@2026} → token
- Railway token: dad474de-a498-4b76-94a0-854f4ca65568 (GraphQL backboard v2, projetos: me.projects.edges)

### Notas produção
- pushTokenCleanup.js já registrado no index.js como job (padrão a seguir)
- Tabelas reais: push_tokens (user_id), pix_accounts (user_id), payout_destinations, withdrawals, reward_events, points_ledger, device_account_aliases — todas com FK user_id sem CASCADE exceto aliase do 008 (support_code_aliases? ON DELETE CASCADE)
- audit_log(action, target_id, admin_id, details, created_at)
