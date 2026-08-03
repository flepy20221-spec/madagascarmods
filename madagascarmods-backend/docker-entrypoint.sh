#!/bin/sh
# =============================================================================
# Entrypoint de producao (Railway).
#
# Aplica as migracoes pendentes e so entao inicia a API. O runner
# src/migrate.js e idempotente: registra o que ja foi aplicado em
# schema_migrations e nao repete nada, portanto e seguro rodar em todo deploy e
# em todo restart.
#
# Se a migracao falhar, o container encerra com codigo diferente de zero. Isso e
# intencional: subir a API sobre um schema incompleto foi exatamente o que
# fazia o callback SSV do AdMob sofrer ROLLBACK por coluna ausente e deixar de
# creditar os pontos, sem qualquer sinal visivel de falha.
# =============================================================================
set -e

echo "[entrypoint] Running database migrations..."
node src/migrate.js

echo "[entrypoint] Starting API server..."
exec node src/index.js
