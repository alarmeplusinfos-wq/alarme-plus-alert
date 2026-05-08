-- ============================================================
-- ALARME ALERTE — Setup Complet Supabase
-- Alarme Plus Internationale
-- Exécutez ce fichier dans Supabase SQL Editor
-- ============================================================

-- ÉTAPE 1: Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ÉTAPE 2: Tables (IF NOT EXISTS = safe à réexécuter)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) DEFAULT 'supabase_auth_managed',
    phone_number VARCHAR(30) NOT NULL,
    profile_photo_url TEXT,
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin', 'superadmin')),
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS user_addresses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    country VARCHAR(100) DEFAULT 'RD Congo',
    province VARCHAR(100),
    ville_territoire VARCHAR(100),
    commune VARCHAR(100),
    quartier VARCHAR(100),
    avenue VARCHAR(200),
    numero_parcelle VARCHAR(50),
    reference_batiment VARCHAR(255),
    additional_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS emergency_contacts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    contact_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    contact_name VARCHAR(255) NOT NULL,
    contact_phone VARCHAR(30) NOT NULL,
    contact_email VARCHAR(255),
    relationship VARCHAR(100),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sos_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    location_accuracy DECIMAL(10, 2),
    address_snapshot TEXT,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'resolved', 'cancelled')),
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS alert_notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID NOT NULL REFERENCES sos_alerts(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES emergency_contacts(id) ON DELETE CASCADE,
    channel VARCHAR(20) DEFAULT 'in_app',
    status VARCHAR(20) DEFAULT 'sent',
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS location_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID NOT NULL REFERENCES sos_alerts(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    latitude DECIMAL(10, 8) NOT NULL,
    longitude DECIMAL(11, 8) NOT NULL,
    accuracy DECIMAL(10, 2),
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL CHECK (type IN (
        'sos_alert', 'contact_request', 'contact_accepted',
        'contact_rejected', 'system', 'security'
    )),
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    related_alert_id UUID REFERENCES sos_alerts(id) ON DELETE SET NULL,
    related_contact_id UUID REFERENCES emergency_contacts(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS activity_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id UUID,
    ip_address TEXT,
    details TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    admin_id UUID NOT NULL REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    target_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    details TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ÉTAPE 3: Index
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_ec_owner ON emergency_contacts(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_ec_email ON emergency_contacts(contact_email);
CREATE INDEX IF NOT EXISTS idx_ec_status ON emergency_contacts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_user ON sos_alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON sos_alerts(status);
CREATE INDEX IF NOT EXISTS idx_notifs_user ON notifications(user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_logs_user ON activity_logs(user_id);

-- ÉTAPE 4: Trigger updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS trg_users_upd ON users;
CREATE TRIGGER trg_users_upd BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trg_addr_upd ON user_addresses;
CREATE TRIGGER trg_addr_upd BEFORE UPDATE ON user_addresses FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trg_ec_upd ON emergency_contacts;
CREATE TRIGGER trg_ec_upd BEFORE UPDATE ON emergency_contacts FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================
-- ÉTAPE 5: Row Level Security (RLS)
-- ============================================================
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_addresses ENABLE ROW LEVEL SECURITY;
ALTER TABLE emergency_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE sos_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE location_history ENABLE ROW LEVEL SECURITY;

-- Drop existing policies to avoid conflicts
DO $$ DECLARE r RECORD; BEGIN
  FOR r IN SELECT policyname, tablename FROM pg_policies WHERE schemaname='public' LOOP
    EXECUTE 'DROP POLICY IF EXISTS ' || quote_ident(r.policyname) || ' ON ' || quote_ident(r.tablename);
  END LOOP;
END $$;

-- USERS
CREATE POLICY "users_own" ON users FOR ALL USING (auth.uid() = id);
CREATE POLICY "users_admin_read" ON users FOR SELECT USING (
  EXISTS (SELECT 1 FROM users WHERE id = auth.uid() AND role IN ('admin','superadmin'))
);
CREATE POLICY "users_admin_write" ON users FOR ALL USING (
  EXISTS (SELECT 1 FROM users WHERE id = auth.uid() AND role IN ('admin','superadmin'))
);

-- USER_ADDRESSES
CREATE POLICY "addr_own" ON user_addresses FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "addr_admin" ON user_addresses FOR SELECT USING (
  EXISTS (SELECT 1 FROM users WHERE id = auth.uid() AND role IN ('admin','superadmin'))
);

-- EMERGENCY_CONTACTS
CREATE POLICY "ec_owner" ON emergency_contacts FOR ALL USING (auth.uid() = owner_user_id);
CREATE POLICY "ec_contact_read" ON emergency_contacts FOR SELECT USING (
  contact_email = (SELECT email FROM users WHERE id = auth.uid())
);
CREATE POLICY "ec_contact_update" ON emergency_contacts FOR UPDATE USING (
  contact_email = (SELECT email FROM users WHERE id = auth.uid())
);
CREATE POLICY "ec_admin" ON emergency_contacts FOR SELECT USING (
  EXISTS (SELECT 1 FROM users WHERE id = auth.uid() AND role IN ('admin','superadmin'))
);

-- SOS_ALERTS
CREATE POLICY "alerts_own" ON sos_alerts FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "alerts_admin" ON sos_alerts FOR ALL USING (
  EXISTS (SELECT 1 FROM users WHERE id = auth.uid() AND role IN ('admin','superadmin'))
);

-- ALERT_NOTIFICATIONS
CREATE POLICY "an_own" ON alert_notifications FOR ALL USING (
  EXISTS (SELECT 1 FROM sos_alerts WHERE id = alert_id AND user_id = auth.uid())
);

-- NOTIFICATIONS
CREATE POLICY "notifs_own" ON notifications FOR ALL USING (auth.uid() = user_id);

-- ACTIVITY_LOGS
CREATE POLICY "logs_insert" ON activity_logs FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "logs_admin" ON activity_logs FOR SELECT USING (
  EXISTS (SELECT 1 FROM users WHERE id = auth.uid() AND role IN ('admin','superadmin'))
);

-- ADMIN_ACTIONS
CREATE POLICY "admin_act" ON admin_actions FOR ALL USING (
  EXISTS (SELECT 1 FROM users WHERE id = auth.uid() AND role IN ('admin','superadmin'))
);

-- LOCATION_HISTORY
CREATE POLICY "loc_own" ON location_history FOR ALL USING (auth.uid() = user_id);

-- ============================================================
-- ÉTAPE 6: Grants
-- ============================================================
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA public TO authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO authenticated;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon;

-- ============================================================
-- ÉTAPE 7: Super Admin
-- Après inscription via l'appli avec admin@alarme-alerte.com
-- Exécutez ceci pour lui donner les droits superadmin:
-- UPDATE users SET role='superadmin' WHERE email='admin@alarme-alerte.com';
-- ============================================================

SELECT 'Configuration ALARME ALERTE terminée avec succès! ✅' as status;
