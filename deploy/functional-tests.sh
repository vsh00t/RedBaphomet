#!/bin/bash
set -e

# Script de pruebas funcionales para RedBaphomet
# Este script verifica que el servidor C2 y el cliente funcionen correctamente

LOG_FILE="/home/redbaphomet/logs/functional-tests.log"
TEST_PASSED=true

echo "[$(date)] Iniciando pruebas funcionales..." | tee -a "$LOG_FILE"

# Función para loggear errores
log_error() {
    echo "[ERROR] $1" | tee -a "$LOG_FILE"
    TEST_PASSED=false
}

# Función para loggear éxito
log_success() {
    echo "[SUCCESS] $1" | tee -a "$LOG_FILE"
}

# Test 1: Verificar que el servidor C2 está en ejecución
echo "[TEST 1] Verificando estado del servidor C2..." | tee -a "$LOG_FILE"
if pgrep -f "sliver-server" > /dev/null; then
    log_success "Servidor C2 está en ejecución"
else
    log_error "Servidor C2 NO está en ejecución"
fi

# Test 2: Verificar que el puerto del C2 está escuchando
echo "[TEST 2] Verificando puerto del C2..." | tee -a "$LOG_FILE"
if ss -tln | grep -q ":31337"; then
    log_success "Puerto 31337 del C2 está escuchando"
else
    log_error "Puerto 31337 del C2 NO está escuchando"
fi

# Test 3: Verificar que el cliente de pruebas está en ejecución
echo "[TEST 3] Verificando estado del cliente de pruebas..." | tee -a "$LOG_FILE"
if pgrep -f "sliver-client" > /dev/null; then
    log_success "Cliente de pruebas está en ejecución"
else
    log_error "Cliente de pruebas NO está en ejecución"
fi

# Test 4: Verificar logs del servidor para errores críticos
echo "[TEST 4] Verificando logs del servidor..." | tee -a "$LOG_FILE"
if grep -qi "error\|panic\|fatal" /home/redbaphomet/logs/server-error.log 2>/dev/null; then
    log_error "Errores críticos encontrados en logs del servidor"
    tail -20 /home/redbaphomet/logs/server-error.log | tee -a "$LOG_FILE"
else
    log_success "No se encontraron errores críticos en logs del servidor"
fi

# Test 5: Verificar que los binarios existen y son ejecutables
echo "[TEST 5] Verificando binarios..." | tee -a "$LOG_FILE"
if [ -x "/home/redbaphomet/bin/sliver-server" ]; then
    log_success "sliver-server existe y es ejecutable"
else
    log_error "sliver-server no existe o no es ejecutable"
fi

if [ -x "/home/redbaphomet/bin/sliver-client" ]; then
    log_success "sliver-client existe y es ejecutable"
else
    log_error "sliver-client no existe o no es ejecutable"
fi

# Test 6: Verificar que el servicio systemd del servidor está activo
echo "[TEST 6] Verificando servicio systemd del servidor..." | tee -a "$LOG_FILE"
if systemctl is-active --quiet redbaphomet-server; then
    log_success "Servicio redbaphomet-server está activo"
else
    log_error "Servicio redbaphomet-server NO está activo"
    systemctl status redbaphomet-server | tail -20 | tee -a "$LOG_FILE"
fi

# Test 7: Verificar que el servicio systemd del cliente está activo
echo "[TEST 7] Verificando servicio systemd del cliente..." | tee -a "$LOG_FILE"
if systemctl is-active --quiet redbaphomet-client; then
    log_success "Servicio redbaphomet-client está activo"
else
    log_error "Servicio redbaphomet-client NO está activo"
    systemctl status redbaphomet-client | tail -20 | tee -a "$LOG_FILE"
fi

# Test 8: Verificar conectividad al servidor C2
echo "[TEST 8] Verificando conectividad al C2..." | tee -a "$LOG_FILE"
if timeout 5 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/31337' 2>/dev/null; then
    log_success "Conexión al servidor C2 exitosa"
else
    log_error "No se pudo conectar al servidor C2"
fi

# Resultado final
echo "[$(date)] Pruebas funcionales completadas." | tee -a "$LOG_FILE"
if [ "$TEST_PASSED" = true ]; then
    log_success "TODAS LAS PRUEBAS PASARON EXITOSAMENTE"
    echo "[$(date)] Pruebas funcionales: PASSED" >> "$LOG_FILE"
    exit 0
else
    log_error "ALGUNAS PRUEBAS FALLARON"
    echo "[$(date)] Pruebas funcionales: FAILED" >> "$LOG_FILE"
    exit 1
fi
