-- Link de convite editavel da missao Manus, separado do portal de comprovacao.
ALTER TABLE missions
  ADD COLUMN IF NOT EXISTS invitation_url TEXT;

UPDATE missions
   SET invitation_url = 'https://manus.im/invitation/56OCV3XMLKTLC?utm_source=invitation&utm_medium=social&utm_campaign=copy_link'
 WHERE slug = 'manus-account-proof'
   AND invitation_url IS NULL;

ALTER TABLE missions
  DROP CONSTRAINT IF EXISTS missions_invitation_url_official;

ALTER TABLE missions
  ADD CONSTRAINT missions_invitation_url_official
  CHECK (
    invitation_url IS NULL
    OR invitation_url ~* '^https://(www\.)?manus\.im/invitation/[A-Za-z0-9_-]+([/?#].*)?$'
  );

COMMENT ON COLUMN missions.invitation_url IS
  'Link oficial de convite do Manus usado pelo portal; editavel no painel de Missoes.';
