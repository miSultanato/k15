# K15 — TCP sequence-window / FIN boundary matrix v0.1

- **Fecha:** 2026-11-25
- **Estado:** matriz diseñada; NOT-RUN.
- **Objetivo:** cerrar el gap de cobertura de exact client-sequence window edges y combinaciones FIN/ACK sin convertirlo en un finding anticipado.
- **Restricción:** solo tráfico sintético hacia guests QEMU/TAP aislados; ningún endpoint de producción. No ejecutar esta matriz desde esta sesión.

## 1. Snapshots comparados

| Rol | Revisión |
|---|---|
| Bounty congelado | ab93479ebc7c85274c722b16897148286d1cfca3 |
| Primer fix upstream | a2d8893261b2be15b44c86d6f4483d65820e943a |
| Upstream actual fijado | cb9f76a5a100c418bfcaeddcd4f137d30ab489d2 |

No cambiar la rama bounty. Los resultados se reportan por revisión y no se mezclan.

## 2. Semántica que debe comprobarse

En el upstream actual, la admisión de sequence number se calcula con aritmética modular de 32 bits:

`delta = SEG.SEQ - C_NXT`

La ventana admitida es inclusiva: [-65,536, +65,535]. Fuera de ella, el paquete debe ir por .oseq/.stale y no consumir ACK, payload, FIN ni advertised window; el guest emite el ACK actual.

En el bounty congelado, el código antiguo no tiene el prefilter equivalente en .est; su ruta .open/.early compara distancia, recorte de datos antiguos y retención de segmentos adelantados. El resultado debe observarse, no asumirse equivalente.

En ambas revisiones:
- FIN consume un número de secuencia después del payload.
- RST tiene una comprobación separada contra el ACK/sequence esperado.
- Una respuesta ACK aislada no prueba que payload/FIN haya sido procesado.

## 3. Cobertura ya existente (no duplicar)

- ACK-window: +1, +63, +64, +65,535, +65,536 respecto de SND.NXT, más forced-wrap; [run 45468109924](https://github.com/miSultanato/k15/actions/runs/45468109924) y [run 45413051340](https://github.com/miSultanato/k15/actions/runs/45413051340).
- RST exacto y offsets -1/+1: [run 45484598190](https://github.com/miSultanato/k15/actions/runs/45484598190).
- FIN/FIN teardown y replay 65 s: [run 45443936657](https://github.com/miSultanato/k15/actions/runs/45443936657).
- SYN-cookie boot reset: [run 45486557359](https://github.com/miSultanato/k15/actions/runs/45486557359).

Estos resultados no sustituyen la matriz de SEG.SEQ ni prueban combinaciones de FIN con ACK fuera de rango.

## 4. Matriz de sequence-number

Para cada caso, crear una conexión cookie-backed independiente, registrar C_NXT/SND.NXT/ACK observados y usar un source port nuevo. En todos los casos capturar ACK, payload HTTP, FIN/RST y estado de conexión.

| ID | SEG.SEQ − C_NXT | Payload | Flags | Oráculo esperado en upstream actual |
|---|---:|---|---|---|
| SQ-01 | -65,537 | 1 byte | ACK | Fuera por abajo: ACK actual; no payload/state update |
| SQ-02 | -65,536 | 1 byte totalmente antiguo | ACK | Límite inferior incluido; los bytes antiguos no avanzan C_NXT |
| SQ-03 | -65,536 | payload que se extiende un byte más allá de C_NXT (65537 bytes) | ACK | Recortar 65.536 bytes antiguos; el byte en C_NXT puede avanzar |
| SQ-04 | -1 | 1 byte antiguo | ACK | No avanzar C_NXT ni entregar byte duplicado |
| SQ-05 | -1 | 1 byte antiguo | FIN+ACK | El FIN queda en C_NXT; comprobar que se consume exactamente una vez |
| SQ-06 | 0 | 1 byte | ACK | In-order: byte procesado y C_NXT avanza uno |
| SQ-07 | 0 | 1 byte | FIN+ACK | In-order FIN: C_NXT avanza payload+1 y cierre coherente |
| SQ-08 | +1 | 1 byte adelantado | ACK | Gap: no entregar fuera de orden; observar hold/retransmisión y luego rellenar gap |
| SQ-09 | +65,535 | 1 byte adelantado | ACK | Límite superior incluido; observar retención/ACK sin atribuir entrega prematura |
| SQ-10 | +65,536 | 1 byte | ACK | Fuera por arriba: ACK actual; no payload/state update |
| SQ-11 | +65,536 | 1 byte | FIN+ACK | FIN fuera de ventana no debe cerrar ni avanzar C_NXT |
| SQ-12 | 0 | 1 byte | FIN+ACK con ACK > SND.NXT | ACK inválido no debe permitir consumir payload/FIN en upstream actual |

Para SQ-08/SQ-09, después del segmento adelantado enviar el hueco que falta y comprobar orden/duplicados. Si la implementación descarta el segmento en vez de retenerlo, registrar el comportamiento exacto y contrastarlo con la semántica declarada antes de clasificarlo como defecto.

## 5. Forced-wrap matrix

Repetir SQ-01, SQ-02, SQ-06, SQ-07, SQ-09, SQ-10 y SQ-12 con C_NXT cerca de ambos lados del wrap:
- C_NXT = 0xFFFF8000 (el rango cruza 0xFFFFFFFF → 0x00000000).
- C_NXT = 0x00008000 (el límite inferior cruza hacia 0xFFFFxxxx).

No usar comparaciones signed del harness para decidir el resultado. Calcular todos los números de secuencia módulo 2^32.

## 6. ACK-window × FIN controls

La matriz actual ya demuestra el defecto de ACK adelantado con payload in-order. Añadir solo los controles que no cubre:
- ACK = SND.NXT exacto, ACK = SND.NXT−1 y ACK = SND.NXT+1;
- ACK antiguo = C_ACK−1 y duplicate = C_ACK;
- cada uno con un payload corto, y FIN+ACK donde la secuencia sea válida.

**Expected:** ACK = SND.NXT+1 (adelantado) no debe avanzar C_ACK ni habilitar payload/FIN en upstream actual. ACK = C_ACK−1 (ligeramente antiguo) no avanza C_ACK, pero puede acompañar payload en secuencia/reordenado dentro del umbral de 2^19; no clasificarlo como ACK adelantado. ACK = C_ACK es duplicate y tampoco avanza C_ACK, aunque el payload in-order puede ser procesado. ACK = SND.NXT y SND.NXT−1 permanecen dentro del rango de ACK pendiente. Separar el ACK antiguo del ACK demasiado adelantado y del criterio SEG.SEQ.

## 7. RST controls

El test existente ya comprueba:
- RST con SEG.SEQ exactamente igual al ACK observado: reset y el resto del request no produce HTTP.
- offsets -1/+1: conexión viva y request completada.

No repetirlo salvo como control en forced-wrap. No convertir un RST exacto en finding.

## 8. Comparación y criterios

Por revisión y por caso, registrar:
- source SHA y QEMU image/build ID;
- C_NXT, C_ACK, C_SND y valores transmitidos;
- delta modular y expected classification;
- respuesta ACK observada;
- payload/HTTP recibido;
- FIN/RST visto y estado final;
- timeout/error stage;
- stdout/stderr/log refs.

Un caso solo pasa si demuestra el estado observable esperado. No inferir procesamiento de payload a partir de un ACK. No inferir cierre de conexión solo por la ausencia de HTTP sin comprobar timeout/FIN/RST.

Un comportamiento distinto entre bounty y upstream requiere una explicación por el diff exacto; no es automáticamente una vulnerabilidad. Para declarar finding hacen falta precondiciones reproducibles, impacto acotado y comparación con el control upstream.

## 9. Orden recomendado de ejecución

1. Ejecutar SQ-01..SQ-12 en current upstream para validar el oráculo del harness.
2. Repetir en primer fix upstream.
3. Repetir en frozen bounty.
4. Repetir forced-wrap solo para casos de borde.
5. Comparar resultados, revisar logs y actualizar findings-summary solo si aparece un comportamiento de seguridad reproducible.
6. Mantener la rama bounty intacta; los tests deben apuntar a imágenes/commits fijados.

**Resultado:** matriz preparada; ninguna prueba ejecutada en esta actualización. Es un coverage task, no un finding.
