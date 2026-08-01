# MadagascarMods Backend API

Backend completo para o aplicativo MadagascarMods, com sistema de pontos, aprovação de e-mail FaucetPay e processamento de saques.

## Tecnologias

- **Runtime:** Node.js 18+
- **Framework:** Express.js
- **Banco de Dados:** PostgreSQL
- **Autenticação:** JWT (Access + Refresh tokens)
- **Deploy:** Railway (Docker)

## Endpoints da API

### Autenticação
| Método | Rota | Descrição |
|--------|------|-----------|
| POST | `/api/auth/login` | Login/registro automático por e-mail |
| POST | `/api/auth/register` | Registro explícito |
| POST | `/api/auth/refresh` | Renovar access token |
| POST | `/api/auth/logout` | Logout e revogação de tokens |

### Usuário
| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/api/users/me` | Perfil completo + saldo + destino |
| GET | `/api/users/balance` | Saldo de pontos |

### Pontos/Recompensas
| Método | Rota | Descrição |
|--------|------|-----------|
| POST | `/api/points/reward` | Creditar pontos por anúncio assistido |
| GET | `/api/points/history` | Histórico de transações |
| GET | `/api/points/stats` | Estatísticas do usuário |

### Destino de Pagamento (FaucetPay)
| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/api/payout-destinations/status` | Status do e-mail FaucetPay |
| POST | `/api/payout-destinations/submit` | Submeter e-mail para aprovação |

### Saques
| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/api/withdrawals` | Histórico de saques |
| POST | `/api/withdrawals/request` | Solicitar saque |
| GET | `/api/withdrawals/eligibility` | Verificar elegibilidade |

### Admin
| Método | Rota | Descrição |
|--------|------|-----------|
| POST | `/api/admin/login` | Login administrativo |
| POST | `/api/admin/setup` | Configuração inicial (1x) |
| GET | `/api/admin/payout-destinations` | Listar e-mails pendentes |
| POST | `/api/admin/payout-destinations/:id/review` | Aprovar/rejeitar e-mail |
| GET | `/api/admin/withdrawals` | Listar saques |
| POST | `/api/admin/withdrawals/:id/approve` | Aprovar saque |
| POST | `/api/admin/withdrawals/:id/reject` | Rejeitar saque (devolve pontos) |
| POST | `/api/admin/withdrawals/:id/process-faucetpay` | Processar pagamento |
| GET | `/api/admin/stats` | Estatísticas gerais |
| GET | `/api/admin/users` | Listar usuários |

### Configuração
| Método | Rota | Descrição |
|--------|------|-----------|
| GET | `/api/config/app` | Configuração pública do app |
| GET | `/api/config/withdrawal` | Config de saque (autenticado) |

## Deploy no Railway

1. Crie um projeto no Railway
2. Adicione um serviço PostgreSQL
3. Configure as variáveis de ambiente (veja `.env.example`)
4. Conecte o repositório GitHub
5. O deploy será automático via Dockerfile

## Migração do Banco

```bash
node src/migrate.js
```

## Variáveis de Ambiente Obrigatórias

- `DATABASE_URL` — Connection string do PostgreSQL
- `JWT_SECRET` — Chave para tokens de acesso
- `JWT_REFRESH_SECRET` — Chave para refresh tokens
- `ENCRYPTION_KEY` — Chave para criptografia de dados sensíveis
