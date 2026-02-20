# Configuración Completa del Framework CI/CD para RedBaphomet

Este documento describe la configuración completa del framework de Continuous Integration/Continuous Deployment (CI/CD) para el proyecto RedBaphomet (fork de Sliver).

## Resumen de la Configuración

### Infraestructura
- **Repositorio GitHub**: https://github.com/vsh00t/RedBaphomet
- **Digital Ocean Droplet**: `redbaphomet-ci`
- **IP del Droplet**: 134.122.2.29
- **Especificaciones Droplet**:
  - Size: s-1vcpu-1gb ($6/mes)
  - RAM: 1GB
  - CPU: 1 vCPU
  - Disco: 25GB
  - SO: Ubuntu 22.04 LTS
  - Región: nyc3

### Arquitectura de Ramas
```
main ← (promoción manual) ← dev ← (PRs con CI) ← feature/*
```

- **master**: Rama original (descontinuada para CI/CD)
- **main**: Rama estable (código probado funcionalmente)
- **dev**: Rama de integración (features que pasan CI + pruebas funcionales)

## Workflows de GitHub Actions

### 1. CI Workflow (.github/workflows/ci.yml)

**Objetivo**: Build y pruebas automatizadas en cada PR hacia `dev` y en cada push a `dev`.

**Triggers**:
- Pull requests hacia `dev`
- Pushes a `dev`
- Filtros de paths: solo archivos Go, Makefile, scripts

**Jobs**:
1. **linux-windows-build-test**: Compila y ejecuta tests en Linux
2. **macos-build-test**: Compila y ejecuta tests en macOS
3. **clients-build**: Compila clientes para múltiples plataformas

### 2. CD Workflow (.github/workflows/cd.yml)

**Objetivo**: Deploy al droplet y ejecución de pruebas funcionales.

**Triggers**: Pushes a `dev` (después de CI exitoso)

**Steps**:
1. Build server y cliente para Linux amd64
2. Copiar binarios al droplet via SCP
3. Copiar script de pruebas funcionales
4. Restart servicios systemd
5. Ejecutar pruebas funcionales remotamente

## Scripts de Configuración

### 1. Setup del Droplet (deploy/setup-droplet.sh)

**Funciones**:
- Crea usuario `redbaphomet`
- Configura sudo sin contraseña
- Instala dependencias (git, build-essential, etc.)
- Clona repositorio en `/home/redbaphomet/RedBaphomet`
- Configura firewall (ufw)
- Crea directorios necesarios

### 2. Servicios Systemd

#### Servidor C2 (deploy/systemd/redbaphomet-server.service)
- Usuario: redbaphomet
- Puerto: 31337
- Restart automático en fallos
- Logging en `/home/redbaphomet/logs/server.log`

#### Cliente de Pruebas (deploy/systemd/redbaphomet-client.service)
- Usuario: redbaphomet
- Se conecta a `127.0.0.1:31337`
- Restart automático en fallos
- Logging en `/home/redbaphomet/logs/client.log`

### 3. Pruebas Funcionales (deploy/functional-tests.sh)

**Verificaciones**:
1. Estado del servidor C2 (proceso corriendo)
2. Puerto del C2 escuchando (31337)
3. Estado del cliente de pruebas
4. Logs del servidor sin errores críticos
5. Binarios existen y son ejecutables
6. Servicios systemd activos
7. Conectividad al servidor C2

## Pasos de Configuración Manual

### Paso 1: Crear SSH Keys para el Droplet

```bash
# Generar par de claves SSH
ssh-keygen -t rsa -b 4096 -f ~/.ssh/redbaphomet_key -N ""

# El contenido de la clave privada se debe agregar a GitHub secret DROPLET_SSH_KEY
# El contenido de la clave pública se debe agregar al droplet
```

### Paso 2: Configurar Secrets en GitHub

Navegar a: https://github.com/vsh00t/RedBaphomet/settings/secrets/actions

**Secrets necesarios**:
- `DROPLET_IP`: 134.122.2.29
- `DROPLET_USER`: redbaphomet
- `DROPLET_SSH_KEY`: (clave privada RSA)

### Paso 3: Configurar el Droplet

```bash
# Conectarse al droplet como root
ssh root@134.122.2.29

# Ejecutar script de setup
sudo bash /home/redbaphomet/RedBaphomet/deploy/setup-droplet.sh

# Instalar servicios systemd
sudo cp /home/redbaphomet/RedBaphomet/deploy/systemd/redbaphomet-server.service /etc/systemd/system/
sudo cp /home/redbaphomet/RedBaphomet/deploy/systemd/redbaphomet-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable redbaphomet-server
sudo systemctl enable redbaphomet-client
```

### Paso 4: Configurar Branch Protection

Usando GitHub CLI o GitHub UI:

```bash
# Proteger rama main
gh api repos/vsh00t/RedBaphomet/branches/main/protection -X PUT \
  -F required_status_checks='{"strict":true,"contexts":["ci"]}' \
  -F enforce_admins=false \
  -F required_pull_request_reviews='{"required_approving_review_count":1}' \
  -F restrictions=null

# Proteger rama dev
gh api repos/vsh00t/RedBaphomet/branches/dev/protection -X PUT \
  -F required_status_checks='{"strict":true,"contexts":["ci","deploy-and-test"]}' \
  -F enforce_admins=false \
  -F required_pull_request_reviews='{"required_approving_review_count":1}' \
  -F restrictions=null
```

## Flujo de Trabajo Completo

### Desarrollo de una Feature

```bash
# 1. Actualizar rama dev local
git fetch origin
git checkout dev
git pull origin dev

# 2. Crear rama de feature
git checkout -b feature/mi-nueva-feature

# 3. Desarrollar y probar localmente
# Escribir código
# Escribir pruebas
make && ./go-tests.sh

# 4. Commit y push
git add .
git commit -m "Add mi nueva feature"
git push origin feature/mi-nueva-feature

# 5. Crear Pull Request en GitHub UI
# PR: feature/mi-nueva-feature → dev
# CI se ejecutará automáticamente
```

### Merge a dev (automático con CI + CD)

1. CI build & tests pasan
2. Code review aprobado
3. Merge a dev
4. CD deploy al droplet + pruebas funcionales
5. Si todo pasa: código está en dev

### Promoción a main (manual)

```bash
# 1. Crear PR: dev → main
# 2. Revisión adicional
# 3. Merge manual a main
# 4. Opcional: etiquetar versión
```

## Costos

- **Digital Ocean Droplet**: ~$6/mes (solo cuando está encendido)
- **GitHub Actions**: Gratis para repositorios públicos
- **GitHub API**: 5000 requests/hour gratis

## Troubleshooting

### Droplet no se conecta
```bash
# Verificar estado del droplet
curl -X GET "https://api.digitalocean.com/v2/droplets/553308559" \
  -H "Authorization: Bearer $DO_API_KEY"

# Verificar firewall
sudo ufw status
```

### Tests fallan en el droplet
```bash
# Ver logs del servidor
cat /home/redbaphomet/logs/server.log
cat /home/redbaphomet/logs/server-error.log

# Ver logs del cliente
cat /home/redbaphomet/logs/client.log
cat /home/redbaphomet/logs/client-error.log

# Ver estado de servicios
sudo systemctl status redbaphomet-server
sudo systemctl status redbaphomet-client

# Ejecutar pruebas funcionales manualmente
bash /home/redbaphomet/functional-tests.sh
```

### CI/CD no funciona
```bash
# Verificar workflows en GitHub
gh run list

# Ver logs específicos de un run
gh run view <run-id> --log
```

## Próximos Pasos

1. ✅ Crear ramas dev y main
2. ✅ Crear workflows de CI/CD
3. ✅ Crear droplet en Digital Ocean
4. ⏳ Configurar secrets en GitHub
5. ⏳ Configurar el droplet manualmente
6. ⏳ Configurar branch protection
7. ⏳ Probar el flujo completo con una feature de ejemplo

## Referencias

- [instrucciones.txt](./instrucciones.txt) - Documento de requisitos original
- [AGENTS.md](./AGENTS.md) - Guías de desarrollo del proyecto
- [Sliver Documentation](https://sliver.sh/docs) - Documentación oficial de Sliver
