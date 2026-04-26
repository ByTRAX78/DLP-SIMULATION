const pool = require('./db');

async function monitor() {
    console.log('Monitor SIEM iniciado - mostrando ultimos eventos cada 3s');
    console.log('Presione Ctrl+C para salir\n');

    let lastId = 0;

    setInterval(async () => {
        try {
            const result = await pool.query(
                'SELECT id, event_type, severity, username, source_ip, created_at FROM security_audit_logs WHERE id > $1 ORDER BY id ASC',
                [lastId]
            );
            for (const row of result.rows) {
                const ts = new Date(row.created_at).toISOString().slice(11, 19);
                const sev = row.severity.padEnd(8);
                const evt = row.event_type.padEnd(25);
                console.log(`[${ts}] ${sev} ${evt} user=${row.username || '-'} ip=${row.source_ip || '-'}`);
                lastId = row.id;
            }
        } catch (err) {
            console.error('Error consultando logs:', err.message);
        }
    }, 3000);
}

monitor();
