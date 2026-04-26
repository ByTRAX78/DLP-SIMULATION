const express = require('express');
const pool = require('./db');
const audit = require('./audit');

const app = express();
app.use(express.json());

const EXFIL_THRESHOLD = 50;

app.use(async (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const username = req.headers['x-username'] || 'anonymous';
    req.clientIp = ip;
    req.username = username;

    if (await audit.isIpBlocked(ip)) {
        await audit.logEvent('BLOCKED_REQUEST', 'HIGH', {
            username, sourceIp: ip, details: { path: req.path }
        });
        return res.status(403).json({ error: 'IP bloqueada por SOAR' });
    }

    if (await audit.isUserBlocked(username)) {
        return res.status(403).json({ error: 'Usuario suspendido por incidente de seguridad' });
    }

    next();
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', service: 'dlp-simulation' });
});

app.get('/api/clientes/:id', async (req, res) => {
    const { id } = req.params;
    const { username, clientIp } = req;

    try {
        const result = await pool.query(
            'SELECT id_cliente, nombre, email, rfc, is_honeytoken FROM clientes WHERE id_cliente = $1',
            [id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Cliente no encontrado' });
        }

        const cliente = result.rows[0];

        if (cliente.is_honeytoken) {
            await audit.logEvent('HONEYTOKEN_ACCESS', 'CRITICAL', {
                username, sourceIp: clientIp,
                targetTable: 'clientes', targetId: cliente.id_cliente,
                query: `SELECT * FROM clientes WHERE id_cliente = ${id}`,
                details: {
                    alert: 'Acceso a registro trampa detectado',
                    record_name: cliente.nombre
                }
            });

            await audit.triggerSoarLockdown(
                clientIp, username,
                `Acceso a honeytoken id=${cliente.id_cliente}`
            );

            return res.status(403).json({
                error: 'Acceso denegado. Incidente registrado.'
            });
        }

        await audit.logEvent('CLIENT_READ', 'INFO', {
            username, sourceIp: clientIp,
            targetTable: 'clientes', targetId: cliente.id_cliente,
            rowsAffected: 1
        });

        res.json({
            id: cliente.id_cliente,
            nombre: cliente.nombre,
            email: cliente.email,
            rfc: cliente.rfc
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/clientes', async (req, res) => {
    const limit = parseInt(req.query.limit) || 10;
    const { username, clientIp } = req;

    try {
        const result = await pool.query(
            'SELECT id_cliente, nombre, email, is_honeytoken FROM clientes LIMIT $1',
            [limit]
        );

        const honeytokenHit = result.rows.find(r => r.is_honeytoken);
        if (honeytokenHit) {
            await audit.logEvent('HONEYTOKEN_BULK_ACCESS', 'CRITICAL', {
                username, sourceIp: clientIp,
                targetTable: 'clientes',
                rowsAffected: result.rowCount,
                details: {
                    alert: 'Honeytoken capturado en consulta masiva',
                    triggered_by: honeytokenHit.id_cliente
                }
            });

            await audit.triggerSoarLockdown(
                clientIp, username,
                `Exfiltracion masiva con honeytoken capturado`
            );

            return res.status(403).json({ error: 'Acceso denegado. Incidente registrado.' });
        }

        if (result.rowCount > EXFIL_THRESHOLD) {
            await audit.logEvent('MASS_EXFIL_SUSPECTED', 'HIGH', {
                username, sourceIp: clientIp,
                targetTable: 'clientes',
                rowsAffected: result.rowCount,
                details: {
                    threshold: EXFIL_THRESHOLD,
                    actual: result.rowCount
                }
            });
        } else {
            await audit.logEvent('CLIENT_LIST_READ', 'INFO', {
                username, sourceIp: clientIp,
                targetTable: 'clientes', rowsAffected: result.rowCount
            });
        }

        res.json(result.rows.filter(r => !r.is_honeytoken));
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/audit/logs', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM security_audit_logs ORDER BY created_at DESC LIMIT 50'
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/audit/critical', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM v_critical_alerts LIMIT 20');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error interno' });
    }
});

app.get('/api/blocked', async (req, res) => {
    try {
        const ips = await pool.query('SELECT * FROM blocked_ips ORDER BY blocked_at DESC');
        const users = await pool.query(
            'SELECT username, role FROM app_users WHERE is_blocked = TRUE'
        );
        res.json({ ips: ips.rows, users: users.rows });
    } catch (err) {
        res.status(500).json({ error: 'Error interno' });
    }
});

app.post('/api/admin/reset', async (req, res) => {
    try {
        await pool.query('DELETE FROM blocked_ips');
        await pool.query('UPDATE app_users SET is_blocked = FALSE');
        await pool.query('DELETE FROM security_audit_logs');
        res.json({ status: 'reset_ok' });
    } catch (err) {
        res.status(500).json({ error: 'Error interno' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor DLP escuchando en puerto ${PORT}`);
    console.log('Endpoints disponibles:');
    console.log('  GET  /api/health');
    console.log('  GET  /api/clientes/:id');
    console.log('  GET  /api/clientes?limit=N');
    console.log('  GET  /api/audit/logs');
    console.log('  GET  /api/audit/critical');
    console.log('  GET  /api/blocked');
    console.log('  POST /api/admin/reset');
});
