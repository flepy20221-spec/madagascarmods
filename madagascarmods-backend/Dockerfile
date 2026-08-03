FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm ci --only=production

COPY src/ ./src/

# A pasta migrations/ precisa existir dentro da imagem: src/migrate.js le os
# arquivos .sql em tempo de execucao. Sem esta copia o runner de migracoes nao
# encontra 003_security_hardening.sql nem
# 004_reward_session_and_withdrawal_hardening.sql, e as colunas
# reward_events.ssv_transaction_id / reward_events.reward_session_id nunca sao
# criadas no banco de producao. A rota SSV depende dessas colunas para creditar
# os pontos do anuncio assistido.
COPY migrations/ ./migrations/

COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

EXPOSE 3000

# O entrypoint aplica as migracoes pendentes antes de subir a API. Se o schema
# estiver incompleto o processo falha ainda no boot, em vez de aceitar trafego
# e perder recompensas silenciosamente por coluna ausente.
ENTRYPOINT ["./docker-entrypoint.sh"]
