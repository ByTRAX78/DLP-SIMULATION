# Simulación DLP - Detección de Fuga de Información

Demostración funcional de un sistema de **prevención de fuga de información (DLP)** con honeytokens, auditoría centralizada y respuesta automatizada (SOAR). Diseñada para acompañar el reporte técnico del ciberejercicio.

## Qué simula

- **Categorización de datos** según ISO/IEC 27001 (Público / Interno / Confidencial / Restringido / Honeytoken).
- **Capa de engaño**: registros trampa insertados en la tabla de clientes.
- **Detección**: cualquier consulta que toque un honeytoken dispara una alerta CRÍTICA.
- **Respuesta automática (SOAR)**: bloqueo de IP + suspensión de usuario en menos de 1 segundo.
- **Auditoría tipo SIEM**: todos los accesos quedan registrados en `security_audit_logs`.

## Requisitos

Solo necesitas:

- Docker Desktop (o Docker Engine) con `docker compose`
- `make` (incluido en macOS y Linux; en Windows usar WSL o Git Bash)

No es necesario instalar Node.js, PostgreSQL, ni ninguna otra dependencia: todo corre dentro de contenedores.

## Cómo levantar el proyecto

```bash
# 1. Levantar PostgreSQL + aplicación
make up

# 2. (En otra terminal) Abrir el monitor SIEM en vivo
make monitor

# 3. (En otra terminal) Ejecutar la simulación del ataque
make attack
```

Verás cómo el atacante:

1. Hace lecturas legítimas (logs INFO).
2. Intenta volcar la tabla completa y captura un honeytoken.
3. La IP queda bloqueada y el usuario suspendido.
4. Las siguientes peticiones reciben `403 Forbidden`.

## Cómo funciona la simulación

### Componentes

| Servicio | Tecnología | Función |
|---|---|---|
| `db` | PostgreSQL 16 | Almacena clientes, honeytokens, logs de auditoría |
| `app` | Node.js + Express | API REST con detección y respuesta automática |

### Flujo de detección

```
Cliente HTTP
    │
    ▼
Middleware Express (verifica IP/usuario bloqueado)
    │
    ▼
Endpoint /api/clientes/:id
    │
    ▼
Consulta a PostgreSQL ──► is_honeytoken = TRUE ?
    │                              │
    │ NO                           │ SÍ
    ▼                              ▼
Log INFO                  Log CRITICAL
                                   │
                                   ▼
                          SOAR Lockdown:
                          - Insert en blocked_ips
                          - UPDATE app_users SET is_blocked=TRUE
                          - Log SOAR_LOCKDOWN
                                   │
                                   ▼
                          HTTP 403 al atacante
```

### Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/clientes/:id` | Lectura individual (puede disparar honeytoken) |
| GET | `/api/clientes?limit=N` | Lectura masiva (umbral de exfiltración) |
| GET | `/api/audit/logs` | Últimos 50 eventos del SIEM |
| GET | `/api/audit/critical` | Solo alertas CRITICAL/HIGH |
| GET | `/api/blocked` | IPs y usuarios actualmente bloqueados |
| POST | `/api/admin/reset` | Limpia logs y desbloqueos (para repetir la demo) |

### Cabeceras simuladas

El atacante envía:

- `X-Forwarded-For: 203.0.113.45` — IP simulada
- `X-Username: analista` — usuario simulado

En producción estas vendrían del JWT y del proxy reverso.

## Comandos del Makefile

```bash
make help      # Lista de comandos
make up        # Levantar el stack
make down      # Detener
make attack    # Ejecutar el ataque simulado
make monitor   # Ver SIEM en tiempo real
make logs      # Logs de la app
make reset     # Limpiar logs y desbloqueos
make psql      # Consola PostgreSQL
make status    # Estado de contenedores
make clean     # Borrar todo (volúmenes incluidos)
```

## Repetir la demo

```bash
make reset     # limpia logs y desbloqueos
make attack    # vuelve a ejecutar el ataque
```

## Inspección manual desde la base de datos

```bash
make psql

dlp_demo=# SELECT event_type, severity, username, source_ip FROM security_audit_logs ORDER BY id DESC LIMIT 10;
dlp_demo=# SELECT * FROM blocked_ips;
dlp_demo=# SELECT username, is_blocked FROM app_users;
```

## Estructura del proyecto

```
dlp-simulation/
├── docker-compose.yml
├── Makefile
├── README.md
├── db/
│   └── init.sql            # DDL: tablas, honeytokens, trigger
└── app/
    ├── Dockerfile
    ├── package.json
    ├── db.js               # Pool de conexión PostgreSQL
    ├── audit.js            # Logger SIEM + acciones SOAR
    ├── server.js           # API Express con detección
    ├── attacker.js         # Simulación del ataque
    └── monitor.js          # Monitor SIEM en tiempo real
```

## Nota

Esta simulación es educativa. En un entorno real las acciones SOAR (`blockIp`, `blockUser`) llamarían a APIs del firewall, IAM corporativo (Okta/Azure AD) y plataformas de notificación (PagerDuty, Slack), no a tablas locales.
