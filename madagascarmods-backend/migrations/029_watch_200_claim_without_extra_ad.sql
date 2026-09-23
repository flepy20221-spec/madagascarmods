-- The 200-ad daily mission already reaches the user's rewarded-ad daily cap.
-- Claiming its 300-point milestone must not require an additional (201st) ad.
UPDATE missions
   SET requires_ad = false,
       updated_at = NOW()
 WHERE id = '00cc8dcd-afe3-45e9-bbb4-7ffc19f79ede'::uuid
   AND type = 'watch_ads'
   AND target_value = 200
   AND is_daily = true
   AND is_active = true;
