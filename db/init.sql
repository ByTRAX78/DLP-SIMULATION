CREATE TABLE data_classification (
    id SERIAL PRIMARY KEY,
    level VARCHAR(20) UNIQUE NOT NULL,
    description TEXT,
    encryption_required BOOLEAN DEFAULT FALSE,
    mfa_required BOOLEAN DEFAULT FALSE
);

INSERT INTO data_classification (level, description, encryption_required, mfa_required) VALUES
('PUBLIC', 'Informacion publica, sin restriccion', FALSE, FALSE),
('INTERNAL', 'Uso interno de la organizacion', FALSE, FALSE),
('CONFIDENTIAL', 'Datos personales (PII) - LFPDPPP', TRUE, TRUE),
('RESTRICTED', 'Datos criticos: bancarios, hashes', TRUE, TRUE),
('HONEYTOKEN', 'Registro trampa para deteccion de fugas', TRUE, TRUE);

CREATE TABLE app_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    is_blocked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'America/Mexico_City')
);

INSERT INTO app_users (username, password_hash, role) VALUES
('admin', '$2b$10$abcdefghijklmnopqrstuv', 'admin'),
('analista', '$2b$10$abcdefghijklmnopqrstuv', 'analyst'),
('soporte', '$2b$10$abcdefghijklmnopqrstuv', 'support');

CREATE TABLE clientes (
    id_cliente SERIAL PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(120) NOT NULL,
    rfc VARCHAR(13),
    telefono VARCHAR(20),
    direccion TEXT,
    classification_id INT REFERENCES data_classification(id) DEFAULT 3,
    is_honeytoken BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'America/Mexico_City')
);

INSERT INTO clientes (nombre, email, rfc, telefono, direccion, classification_id, is_honeytoken) VALUES
('Maria Lopez', 'maria.lopez@example.com', 'LOPM850101AB1', '5512345678', 'Av. Reforma 100, CDMX', 3, FALSE),
('Carlos Ramirez', 'carlos.r@example.com', 'RACA900215CD2', '5523456789', 'Calle Hidalgo 45, GDL', 3, FALSE),
('Ana Torres', 'ana.torres@example.com', 'TOAA920330EF3', '5534567890', 'Blvd. Diaz Ordaz 200, MTY', 3, FALSE),
('Jose Hernandez', 'jose.h@example.com', 'HEJO880712GH4', '5545678901', 'Av. Universidad 500, CDMX', 3, FALSE),
('Laura Gomez', 'laura.g@example.com', 'GOLA950825IJ5', '5556789012', 'Calle Juarez 78, PUE', 3, FALSE),
('HONEYPOT_USER_TRAP', 'honeypot.trap@security-canary.local', 'XXXX000000XXX', '0000000000', 'NO REAL ADDRESS', 5, TRUE),
('CANARY_RECORD_001', 'canary.alert@security-canary.local', 'YYYY000000YYY', '0000000000', 'NO REAL ADDRESS', 5, TRUE);

CREATE TABLE security_audit_logs (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    username VARCHAR(50),
    source_ip VARCHAR(45),
    target_table VARCHAR(50),
    target_id INT,
    query_executed TEXT,
    rows_affected INT,
    details JSONB,
    created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'America/Mexico_City')
);

CREATE INDEX idx_audit_severity ON security_audit_logs(severity);
CREATE INDEX idx_audit_event_type ON security_audit_logs(event_type);
CREATE INDEX idx_audit_created_at ON security_audit_logs(created_at);

CREATE TABLE blocked_ips (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    reason TEXT,
    blocked_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'America/Mexico_City')
);

CREATE OR REPLACE FUNCTION log_client_access()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.is_honeytoken = TRUE THEN
        INSERT INTO security_audit_logs (event_type, severity, target_table, target_id, details)
        VALUES ('HONEYTOKEN_INSERT', 'CRITICAL', 'clientes', NEW.id_cliente,
                jsonb_build_object('alert', 'Honeytoken record created', 'record', NEW.nombre));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_honeytoken_insert
AFTER INSERT ON clientes
FOR EACH ROW
EXECUTE FUNCTION log_client_access();

CREATE OR REPLACE VIEW v_critical_alerts AS
SELECT id, event_type, severity, username, source_ip, target_table, target_id, details, created_at
FROM security_audit_logs
WHERE severity IN ('CRITICAL', 'HIGH')
ORDER BY created_at DESC;