.PHONY: help up down logs attack monitor reset psql clean status

help:
	@echo "Comandos disponibles:"
	@echo "  make up       - Levantar el ambiente (PostgreSQL + App Node.js)"
	@echo "  make down     - Detener todos los contenedores"
	@echo "  make attack   - Ejecutar la simulacion del ataque"
	@echo "  make monitor  - Ver el SIEM en tiempo real"
	@echo "  make logs     - Ver logs de la aplicacion"
	@echo "  make reset    - Limpiar logs y desbloquear usuarios/IPs"
	@echo "  make psql     - Abrir consola PostgreSQL"
	@echo "  make status   - Ver estado de los contenedores"
	@echo "  make clean    - Eliminar contenedores, volumenes e imagenes"

up:
	docker compose up -d --build
	@echo "Esperando que la app este lista..."
	@sleep 5
	@curl -s http://localhost:3000/api/health || echo "App aun no responde, intentar de nuevo en unos segundos"

down:
	docker compose down

logs:
	docker compose logs -f app

attack:
	@docker compose exec app node attacker.js

monitor:
	@docker compose exec app node monitor.js

reset:
	@curl -s -X POST http://localhost:3000/api/admin/reset
	@echo " - Estado reiniciado"

psql:
	docker compose exec db psql -U dlp_admin -d dlp_demo

status:
	docker compose ps

clean:
	docker compose down -v --rmi local
