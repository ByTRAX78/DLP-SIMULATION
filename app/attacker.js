const http = require('http');

const TARGET = process.env.TARGET || 'http://app:3000';
const ATTACKER_USER = 'analista';
const ATTACKER_IP = '203.0.113.45';

function request(path, method = 'GET') {
    return new Promise((resolve, reject) => {
        const url = new URL(TARGET + path);
        const opts = {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname + url.search,
            method: method,
            headers: {
                'X-Forwarded-For': ATTACKER_IP,
                'X-Username': ATTACKER_USER
            }
        };
        const req = http.request(opts, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(body) }); }
                catch { resolve({ status: res.statusCode, body }); }
            });
        });
        req.on('error', reject);
        req.end();
    });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function attack() {
    console.log('\n##############################################');
    console.log('#  SIMULACION DE ATAQUE - FUGA DE INFORMACION');
    console.log('##############################################');
    console.log(`Atacante: ${ATTACKER_USER} desde ${ATTACKER_IP}\n`);

    console.log('[Fase 1] Reconocimiento - lectura individual legitima');
    let r = await request('/api/clientes/1');
    console.log(`  GET /api/clientes/1  -> ${r.status}  ${JSON.stringify(r.body)}`);
    await sleep(500);

    r = await request('/api/clientes/2');
    console.log(`  GET /api/clientes/2  -> ${r.status}  ${JSON.stringify(r.body)}`);
    await sleep(500);

    console.log('\n[Fase 2] Exfiltracion masiva - intento de volcar tabla completa');
    r = await request('/api/clientes?limit=100');
    console.log(`  GET /api/clientes?limit=100  -> ${r.status}`);
    if (r.status === 200) {
        console.log(`  Registros recibidos: ${Array.isArray(r.body) ? r.body.length : 'n/a'}`);
    } else {
        console.log(`  Respuesta: ${JSON.stringify(r.body)}`);
    }
    await sleep(1000);

    console.log('\n[Fase 3] Verificacion del estado tras la deteccion');
    r = await request('/api/clientes/1');
    console.log(`  GET /api/clientes/1  -> ${r.status}  ${JSON.stringify(r.body)}`);

    console.log('\n[Fase 4] Reporte de bloqueos activos');
    r = await request('/api/blocked');
    console.log(`  GET /api/blocked  -> ${r.status}`);
    console.log(`  ${JSON.stringify(r.body, null, 2)}`);

    console.log('\n[Fase 5] Alertas criticas registradas en SIEM');
    r = await request('/api/audit/critical');
    console.log(`  Total alertas criticas: ${Array.isArray(r.body) ? r.body.length : 0}`);
    if (Array.isArray(r.body)) {
        r.body.slice(0, 5).forEach(a => {
            console.log(`  - [${a.severity}] ${a.event_type} | user=${a.username} ip=${a.source_ip}`);
        });
    }

    console.log('\n##############################################');
    console.log('#  SIMULACION COMPLETADA');
    console.log('##############################################\n');
}

attack().catch(err => {
    console.error('Error en simulacion:', err.message);
    process.exit(1);
});
