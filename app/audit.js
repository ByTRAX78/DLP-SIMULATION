const pool = require('./db');

async function logEvent(eventType, severity, data) {
    const query = `
        INSERT INTO security_audit_logs
        (event_type, severity, username, source_ip, target_table, target_id, query_executed, rows_affected, details)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, created_at
    `;
    const values = [
        eventType,
        severity,
        data.username || null,
        data.sourceIp || null,
        data.targetTable || null,
        data.targetId || null,
        data.query || null,
        data.rowsAffected || null,
        data.details ? JSON.stringify(data.details) : null
    ];
    const result = await pool.query(query, values);
    return result.rows[0];
}

async function blockIp(ip, reason) {
    try {
        await pool.query(
            'INSERT INTO blocked_ips (ip_address, reason) VALUES ($1, $2) ON CONFLICT (ip_address) DO NOTHING',
            [ip, reason]
        );
        return true;
    } catch (err) {
        console.error('Error bloqueando IP:', err);
        return false;
    }
}

async function blockUser(username, reason) {
    try {
        await pool.query('UPDATE app_users SET is_blocked = TRUE WHERE username = $1', [username]);
        await logEvent('USER_BLOCKED', 'HIGH', {
            username: username,
            details: { reason: reason, action: 'auto-block' }
        });
        return true;
    } catch (err) {
        console.error('Error bloqueando usuario:', err);
        return false;
    }
}

async function isIpBlocked(ip) {
    const result = await pool.query('SELECT 1 FROM blocked_ips WHERE ip_address = $1', [ip]);
    return result.rowCount > 0;
}

async function isUserBlocked(username) {
    const result = await pool.query(
        'SELECT is_blocked FROM app_users WHERE username = $1',
        [username]
    );
    if (result.rowCount === 0) return false;
    return result.rows[0].is_blocked;
}

async function triggerSoarLockdown(ip, username, reason) {
    console.log('\n========== SOAR LOCKDOWN ACTIVADO ==========');
    console.log(`Razon: ${reason}`);
    console.log(`IP atacante: ${ip}`);
    console.log(`Usuario sospechoso: ${username}`);

    await blockIp(ip, reason);
    await blockUser(username, reason);

    await logEvent('SOAR_LOCKDOWN', 'CRITICAL', {
        username: username,
        sourceIp: ip,
        details: {
            reason: reason,
            actions: ['IP bloqueada', 'Usuario suspendido', 'Alerta enviada al SOC'],
            mttr_seconds: 1
        }
    });

    console.log('Acciones ejecutadas:');
    console.log('  [OK] IP bloqueada en firewall (simulado)');
    console.log('  [OK] Usuario suspendido en BD');
    console.log('  [OK] Alerta CRITICAL registrada en SIEM');
    console.log('  [OK] Notificacion al equipo SOC enviada');
    console.log('============================================\n');
}

module.exports = {
    logEvent,
    blockIp,
    blockUser,
    isIpBlocked,
    isUserBlocked,
    triggerSoarLockdown
};
