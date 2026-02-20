# Scripts de Despliegue y Configuración

Este directorio contiene los scripts necesarios para configurar y mantener el entorno de CI/CD de RedBaphomet en el Droplet de Digital Ocean.

## Archivos

### 1. setup-droplet.sh
Script de inicialización del Droplet.

**Uso**:
```bash
# Como root en el droplet
sudo bash setup-droplet.sh
```

**Qué hace**:
- Crea usuario `redbaphomet`
- Configura sudo sin contraseña
- Instala dependencias necesarias
- Configura firewall
- Prepara directorios y repositorio

### 2. systemd/redbaphomet-server.service
Archivo de servicio systemd para el servidor C2.

**Instalación**:
```bash
sudo cp systemd/redbaphomet-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable redbaphomet-server
sudo systemctl start redbaphomet-server
```

**Gestión**:
```bash
sudo systemctl status redbaphomet-server
sudo systemctl restart redbaphomet-server
sudo systemctl stop redbaphomet-server
sudo systemctl logs redbaphomet-server -f
```

### 3. systemd/redbaphomet-client.service
Archivo de servicio systemd para el cliente de pruebas.

**Instalación**:
```bash
sudo cp systemd/redbaphomet-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable redbaphomet-client
sudo systemctl start redbaphomet-client
```

**Gestión**:
```bash
sudo systemctl status redbaphomet-client
sudo systemctl restart redbaphomet-client
sudo systemctl stop redbaphomet-client
sudo systemctl logs redbaphomet-client -f
```

### 4. functional-tests.sh
Script de pruebas funcionales que verifica el estado del sistema.

**Uso**:
```bash
# Como usuario redbaphomet
bash /home/redbaphomet/functional-tests.sh
```

**Pruebas realizadas**:
1. Verifica que el servidor C2 está corriendo
2. Verifica que el puerto 31337 está escuchando
3. Verifica que el cliente de pruebas está corriendo
4. Revisa logs del servidor por errores
5. Verifica que los binarios existen
6. Verifica que los servicios systemd están activos
7. Verifica conectividad al servidor C2

**Exit code**:
- 0: Todas las pruebas pasaron
- 1: Alguna prueba falló

## Proceso de Deploy Manual

Si necesitas hacer deploy manual al droplet:

```bash
# 1. Build localmente
make clean && make linux-amd64
make client GOOS=linux GOARCH=amd64

# 2. Copiar binarios al droplet
scp sliver-server redbaphomet@134.122.2.29:/home/redbaphomet/bin/
scp sliver-client redbaphomet@134.122.2.29:/home/redbaphomet/bin/

# 3. Restart servicios en el droplet
ssh redbaphomet@134.122.2.29 "sudo systemctl restart redbaphomet-server"
ssh redbaphomet@134.122.2.29 "sudo systemctl restart redbaphomet-client"

# 4. Ejecutar pruebas funcionales
ssh redbaphomet@134.122.2.29 "bash /home/redbaphomet/functional-tests.sh"
```

## Logs

Todos los logs se guardan en `/home/redbaphomet/logs/`:

- `server.log`: Logs estándar del servidor C2
- `server-error.log`: Logs de error del servidor C2
- `client.log`: Logs estándar del cliente de pruebas
- `client-error.log`: Logs de error del cliente de pruebas
- `functional-tests.log`: Logs de las pruebas funcionales

**Ver logs en tiempo real**:
```bash
ssh redbaphomet@134.122.2.29 "tail -f /home/redbaphomet/logs/server.log"
```

## Troubleshooting

### Servidor no inicia
```bash
# Verificar logs de errores
cat /home/redbaphomet/logs/server-error.log

# Verificar que el binario existe y es ejecutable
ls -la /home/redbaphomet/bin/sliver-server

# Verificar puerto en uso
sudo netstat -tlnp | grep 31337
```

### Cliente no se conecta
```bash
# Verificar logs de errores
cat /home/redbaphomet/logs/client-error.log

# Verificar conectividad
telnet 127.0.0.1 31337

# Verificar que el servidor está corriendo
ps aux | grep sliver-server
```

### Tests fallan
```bash
# Ejecutar con más detalle
bash -x /home/redbaphomet/functional-tests.sh

# Ver logs del test
cat /home/redbaphomet/logs/functional-tests.log
```

## Seguridad

- Los servicios corren bajo el usuario `redbaphomet` (no root)
- El firewall solo permite puertos 22 (SSH) y 31337 (C2)
- Los logs rotan automáticamente según configuración de systemd
- SSH key privada debe guardarse en GitHub secrets, nunca en el repo
