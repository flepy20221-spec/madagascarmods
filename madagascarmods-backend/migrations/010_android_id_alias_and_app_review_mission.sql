-- ============================================================================
-- 010 — Alias estavel por ANDROID_ID e missao de avaliacao na Play Store
--
-- Esta migracao resolve dois problemas distintos e nao relacionados entre si.
-- Eles vem juntos porque foram diagnosticados e corrigidos no mesmo ciclo, e
-- porque ambos sao puramente aditivos: nenhuma conta, saldo, alias, missao ou
-- progresso existente e alterado ou removido por este arquivo.
--
-- ============================================================================
-- PARTE 1 — POR QUE A PONTUACAO DESAPARECEU NA VERSAO 1.7.4
--
-- Diagnostico medido na base de producao antes desta migracao:
--
--   SELECT user_id, COUNT(*) FROM device_account_aliases
--    GROUP BY user_id HAVING COUNT(*) > 1;
--   -> 0 linhas
--
-- Zero contas com mais de um alias, em 537 contas e 508 chaves de aparelho.
-- Isso significa que o mecanismo de rotacao de chave introduzido na migracao
-- 008 nunca foi exercitado com sucesso: toda vez que a chave do aparelho mudou,
-- o servidor criou uma conta nova em vez de registrar a chave nova como alias da
-- conta existente. Um unico aparelho de teste (motorola moto g15) acumulou sete
-- contas, com 384, 278, 169, 34, 29, 16 e 0 pontos.
--
-- A causa e uma propriedade do proprio Android, nao um erro de calculo. Desde o
-- Android 8, Settings.Secure.ANDROID_ID e escopado pela combinacao
--
--     aparelho + usuario do sistema + CHAVE DE ASSINATURA do aplicativo
--
-- Trocar a keystore de release, alternar entre build de debug e de release, ou
-- limpar os dados do app produz um ANDROID_ID diferente. Como
-- `device_account_key` era o SHA-256 desse valor, a chave mudava junto e nenhuma
-- prova de posse sobrevivia: o refresh token e o token de vinculo ficam no
-- armazenamento seguro, que a desinstalacao apaga, e o marcador em
-- SharedPreferences tambem e removido pelo sistema na desinstalacao. O
-- aplicativo entao declarava `fresh_install` de forma tecnicamente correta, e o
-- servidor obedecia criando conta nova com saldo zero.
--
-- O QUE ESTA MIGRACAO ACRESCENTA
--
-- Um segundo alias, `android_id_key`, derivado do ANDROID_ID com um escopo que
-- NAO carrega numero de versao:
--
--     device_account_key = sha256('cashpix|com.madagascarmods|v2|' + androidId)
--     android_id_key     = sha256('cashpix-android-id|' + androidId)
--
-- Os dois valores continuam sendo hashes: o ANDROID_ID bruto nunca chega ao
-- banco, e o `android_id_key` tambem nao permite reconstruir o valor original.
--
-- O ganho e concreto e limitado, e vale enunciar os dois lados:
--
--   * GANHO — o escopo `v2` deixa de ser um ponto de ruptura. Qualquer evolucao
--     futura do formato da chave principal (v3, mudanca de sal, mudanca de
--     algoritmo) passa a ter um caminho de reconhecimento independente, e a
--     conta continua sendo encontrada pelo alias secundario.
--
--   * LIMITE — quando a CHAVE DE ASSINATURA muda, o proprio ANDROID_ID muda, e
--     por consequencia os dois hashes mudam juntos. Nenhum hash do ANDROID_ID
--     sobrevive a uma troca de keystore. Isso e uma propriedade do Android e
--     nao ha correcao possivel no servidor. A protecao contra esse caso e o
--     token de vinculo restaurado pelo Auto Backup do Android, tratado no lado
--     do aplicativo, mais a reconciliacao manual pelo painel.
--
-- Registrar essa limitacao aqui e deliberado: sem ela, a proxima pessoa a ler
-- este arquivo concluiria que o problema esta integralmente resolvido no banco.
--
-- ============================================================================
-- PARTE 2 — MISSAO DE AVALIACAO NA PLAY STORE
--
-- A tabela `missions` foi desenhada para metas contaveis: assistir N anuncios,
-- fazer check-in, convidar N amigos, alcancar um nivel. O progresso de todos os
-- tipos existentes e derivado de dados que o servidor ja possui e pode auditar.
--
-- Avaliar o aplicativo na Play Store nao tem essa propriedade. O Google nao
-- oferece nenhuma API que informe se um usuario especifico avaliou o app, e a
-- In-App Review API do proprio Google nao revela se o usuario enviou a
-- avaliacao nem qual nota deu — isso e uma decisao de privacidade da plataforma,
-- nao uma limitacao contornavel.
--
-- Consequencia honesta, que precisa estar escrita no schema: esta missao e
-- SEMPRE autodeclarada. As colunas abaixo existem para tornar esse fato
-- explicito e auditavel, em vez de deixar a impressao de uma verificacao que
-- nao existe.
--
--   verification_mode  'auto'          progresso calculado pelo servidor a
--                                      partir de dados proprios (todos os tipos
--                                      atuais)
--                      'self_declared' o servidor registra a intencao e a
--                                      passagem pela loja, sem confirmar o ato
--
--   action_url         destino externo da missao. Validado na aplicacao para
--                      aceitar apenas a ficha oficial do pacote, impedindo que
--                      um erro de digitacao no painel envie a base para uma URL
--                      arbitraria.
--
--   requires_ad        hoje o resgate de QUALQUER missao exige assistir um
--                      anuncio, com a regra fixa no codigo. Para a missao de
--                      avaliacao isso e indesejavel: o usuario ja saiu do app,
--                      avaliou e voltou. A coluna devolve essa decisao ao
--                      administrador, mantendo `true` como padrao para nao
--                      alterar o comportamento de nenhuma missao existente.
--
--   cooldown_days      permite repetir a missao apos N dias. NULL preserva o
--                      comportamento atual (uma vez por conta, ou por dia
--                      quando is_daily).
--
--   min_seconds_before_claim
--                      intervalo minimo entre abrir a loja e resgatar. E a
--                      unica barreira antifraude possivel aqui: sem ela, um
--                      cliente adulterado chamaria start e claim em sequencia
--                      imediata. Nao prova que a avaliacao aconteceu; apenas
--                      torna o atalho automatizado detectavel e mais custoso.
--
-- A tabela mission_progress ganha `started_at` para registrar o instante em que
-- a loja foi aberta, que e o dado que sustenta a checagem de intervalo minimo.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- PARTE 1 — alias secundario derivado do ANDROID_ID
-- ----------------------------------------------------------------------------

-- A tabela device_account_aliases (migracao 008) ja aceita qualquer hash de 64
-- caracteres como chave. O alias novo nao exige coluna nova: ele e outra linha,
-- distinguida pela coluna `source`. O que falta e poder registrar de onde o
-- alias veio, para que uma investigacao futura consiga separar chave principal
-- de alias derivado do ANDROID_ID sem adivinhar pelo valor.
--
-- `source` e VARCHAR livre e ja recebe valores como 'account_created',
-- 'device_login', 'binding_token'. O valor novo e 'android_id_key'. Nenhuma
-- constraint precisa mudar.

COMMENT ON COLUMN device_account_aliases.source IS
  'Origem do alias: account_created, device_login, device_alias, binding_token, '
  'refresh_token, legacy_device_id, android_id_key (SHA-256 do ANDROID_ID com '
  'escopo sem versao) ou admin_manual.';

-- Indice de apoio para a busca por alias feita em /auth/device. A PRIMARY KEY
-- de device_account_key ja resolve a busca principal; este indice acelera a
-- varredura por user_id usada na reconciliacao de contas pelo painel, que hoje
-- faz sequential scan em toda a tabela.
CREATE INDEX IF NOT EXISTS idx_device_account_aliases_user_id
  ON device_account_aliases(user_id);

-- Registro explicito de que a conta ja apresentou um alias de ANDROID_ID. Serve
-- ao diagnostico: permite responder "quantas contas da base ja passaram pelo
-- mecanismo novo" com uma consulta simples, sem inferir pela tabela de aliases.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS android_id_key CHAR(64);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_android_id_key_unique
  ON users(android_id_key)
  WHERE android_id_key IS NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conname = 'users_android_id_key_format'
       AND conrelid = 'users'::regclass
  ) THEN
    -- NOT VALID: a constraint passa a valer para toda escrita nova sem exigir
    -- varredura da tabela inteira no deploy. As linhas existentes tem NULL
    -- nesta coluna e portanto ja satisfazem a condicao.
    ALTER TABLE users
      ADD CONSTRAINT users_android_id_key_format
      CHECK (android_id_key IS NULL OR android_id_key ~ '^[a-f0-9]{64}$')
      NOT VALID;
  END IF;
END
$$;

COMMENT ON COLUMN users.android_id_key IS
  'SHA-256 do ANDROID_ID com escopo sem versao. Alias secundario de '
  'reconhecimento do aparelho. Muda quando a chave de assinatura do APK muda, '
  'pelo mesmo motivo que device_account_key muda.';

-- ----------------------------------------------------------------------------
-- PARTE 2 — colunas da missao de avaliacao
-- ----------------------------------------------------------------------------

ALTER TABLE missions
  ADD COLUMN IF NOT EXISTS verification_mode VARCHAR(20) NOT NULL DEFAULT 'auto',
  ADD COLUMN IF NOT EXISTS action_url TEXT,
  ADD COLUMN IF NOT EXISTS requires_ad BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS cooldown_days INTEGER,
  ADD COLUMN IF NOT EXISTS min_seconds_before_claim INTEGER NOT NULL DEFAULT 0;

-- Os defaults acima foram escolhidos para que as sete missoes ja existentes em
-- producao continuem se comportando exatamente como antes desta migracao:
-- verificacao automatica, anuncio obrigatorio, sem cooldown e sem espera.

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'missions_verification_mode_valid'
       AND conrelid = 'missions'::regclass
  ) THEN
    ALTER TABLE missions
      ADD CONSTRAINT missions_verification_mode_valid
      CHECK (verification_mode IN ('auto', 'self_declared'));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'missions_cooldown_days_positive'
       AND conrelid = 'missions'::regclass
  ) THEN
    ALTER TABLE missions
      ADD CONSTRAINT missions_cooldown_days_positive
      CHECK (cooldown_days IS NULL OR cooldown_days > 0);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'missions_min_seconds_before_claim_range'
       AND conrelid = 'missions'::regclass
  ) THEN
    -- Teto de uma hora. Um valor digitado por engano no painel (por exemplo
    -- 86400 em vez de 15) tornaria a missao impossivel de resgatar sem que
    -- ninguem entendesse o motivo.
    ALTER TABLE missions
      ADD CONSTRAINT missions_min_seconds_before_claim_range
      CHECK (min_seconds_before_claim >= 0 AND min_seconds_before_claim <= 3600);
  END IF;
END
$$;

COMMENT ON COLUMN missions.verification_mode IS
  'auto: progresso calculado pelo servidor. self_declared: o servidor registra a '
  'passagem pela acao externa sem poder confirmar que ela ocorreu.';
COMMENT ON COLUMN missions.action_url IS
  'Destino externo aberto pelo aplicativo. Validado na aplicacao contra a ficha '
  'oficial do pacote.';
COMMENT ON COLUMN missions.requires_ad IS
  'Exige anuncio recompensado antes do resgate. Padrao true para preservar o '
  'comportamento das missoes existentes.';
COMMENT ON COLUMN missions.cooldown_days IS
  'Dias para a missao ficar disponivel novamente. NULL = comportamento atual.';
COMMENT ON COLUMN missions.min_seconds_before_claim IS
  'Intervalo minimo entre iniciar a acao externa e resgatar a recompensa.';

-- ----------------------------------------------------------------------------
-- PARTE 3 — instante de inicio da acao externa
-- ----------------------------------------------------------------------------

ALTER TABLE mission_progress
  ADD COLUMN IF NOT EXISTS started_at TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN mission_progress.started_at IS
  'Momento em que o usuario iniciou a acao externa da missao (abriu a loja). '
  'Base da checagem de min_seconds_before_claim.';

-- ----------------------------------------------------------------------------
-- PARTE 4 — a missao de avaliacao
--
-- Criada como INATIVA de proposito. Ela aparece no painel para o administrador
-- revisar titulo, recompensa e URL, e so entao publicar. Uma missao que credita
-- pontos nao deve entrar no ar por efeito colateral de uma migracao.
--
-- A insercao e condicional: se uma missao app_review ja existir (por exemplo
-- criada manualmente pelo painel antes deste deploy), nada e sobrescrito.
-- ----------------------------------------------------------------------------

INSERT INTO missions (
  title, description, type, target_value, reward_points, icon,
  is_active, is_daily, sort_order,
  verification_mode, action_url, requires_ad, cooldown_days,
  min_seconds_before_claim
)
SELECT
  'Avalie o CashPix na Play Store',
  'Deixe sua avaliacao na loja e ganhe pontos. Toque para abrir a Play Store.',
  'app_review',
  1,
  500,
  'rate_review',
  false,   -- inativa: o administrador publica quando quiser
  false,   -- nao e diaria
  7,       -- depois das seis missoes existentes (sort_order 0..6)
  'self_declared',
  'https://play.google.com/store/apps/details?id=com.madagascarmods',
  false,   -- o usuario ja saiu do app e voltou; nao exigir anuncio tambem
  NULL,    -- uma vez por conta
  15       -- 15s entre abrir a loja e resgatar
WHERE NOT EXISTS (
  SELECT 1 FROM missions WHERE type = 'app_review'
);
