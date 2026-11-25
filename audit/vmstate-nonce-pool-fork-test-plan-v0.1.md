# K15 — Full VM-state nonce-pool fork/restore test plan v0.1

- **Fecha:** 2026-11-25
- **Estado:** plan de validación preparado; NOT-RUN.
- **Target:** frozen bounty SHA ab93479ebc7c85274c722b16897148286d1cfca3.
- **Restricción:** solo imagen sintética local/QEMU; no usar host, key, certificado ni tráfico de producción.

## 1. Pregunta exacta

¿Dos guests que reanudan desde el mismo snapshot de RAM completa, tomado con una entrada ECDSA nonce-pool aún pendiente, pueden consumir el mismo par precomputado POOLR/POOLK para firmar dos transcript hashes distintos con la misma clave sintética?

La precondición de estado en RAM está confirmada por [nonce-pool-rollback-review.md](nonce-pool-rollback-review.md). La duplicación real del uso de un slot sigue NOT-TESTED.

## 2. Por qué disk snapshot/pmemsave no bastan

- tools/vm.sh usa un disco raw con snapshot=on; esto evita persistir cambios del disco, pero no crea por sí solo una copia completa de RAM/vCPU/device state.
- pmemsave captura bytes de RAM, pero no restaura un guest ejecutable ni duplica los contadores.
- La prueba requiere QEMU migration/save-restore de RAM y device state, con máquina/dispositivos compatibles en origen y destino.
- Se necesitan dos destinos independientes restaurados desde el mismo stream, cada uno con TAP/user-net aislado.

Referencia de QEMU migration: https://www.qemu.org/docs/master/devel/migration/main.html

## 3. Estado que debe congelarse

Antes del snapshot, el parser read-only debe registrar para cada vCPU:
- runtime BSS base derivada del build/LOW real;
- POOLN;
- POOLFILL;
- índice de la siguiente entrada que consumirá sign;
- hash/fingerprint de la siguiente entrada POOLR/POOLK, sin volcar el nonce raw;
- que el private scalar corresponde únicamente a la clave sintética del build.

No hardcodear LOW ni direcciones de otra compilación. El parser debe comprobar límites y offsets contra el mapa de memoria del artefacto exacto.

Preferir SMP=1 para la primera prueba, para fijar el pool que consume el primer handshake. Si el test solo pasa con SMP=1, registrar que no cubre la asignación multi-vCPU. La prueba SMP>1 requiere instrumentación read-only del vCPU/pool seleccionado.

## 4. Fork de dos ramas

1. Construir una imagen sintética del commit bounty fijado; verificar hash de build y certificado/clave generados.
2. Arrancar una VM QEMU TCG local con la configuración de tools/vm.sh, pero añadir un QMP socket y capacidad de migration.
3. Esperar a que el pool esté poblado y verificar POOLN > 0. El health-check inicial puede haber consumido una firma; registrar el contador posterior, no asumir POOLN=64.
4. Guardar un migration stream completo entre firmas. No usar únicamente snapshot de disco ni pmemsave.
5. Crear dos copias idénticas del stream y restaurarlas en dos QEMU destinations con configuración de máquina/dispositivos equivalente y backends de red aislados.
6. En cada rama, abrir exactamente una conexión TLS nueva con ClientHello distinto; usar el mismo certificado/clave sintéticos y hacer que cada guest firme su CertificateVerify.
7. Capturar las firmas y transcript fingerprints localmente.
8. Verificar ambas firmas con la clave pública sintética; calcular nonce efectivo con la clave privada sintética en el harness.
9. Comparar fingerprints de (r, nonce) y exigir transcript hashes distintos. El resultado no debe imprimir ni subir nonce, clave, firma o captures.
10. Apagar y limpiar ambos guests, migration streams, overlays, sockets y temporales.

## 5. Uso del harness existente

audit/qemu_nonce_uniqueness.py ya:
- captura handshake TLS;
- extrae/verifica CertificateVerify;
- recupera el nonce ECDSA usando solo la clave sintética local;
- puede escribir fingerprints SHA-256 de (r, nonce) con FINGERPRINT_PATH;
- imprime únicamente contadores y fingerprints unidireccionales.

Para el fork test:
- ejecutar COUNT=1, WORKERS=1 en cada rama;
- escribir un fingerprint distinto por rama;
- extender el harness solo si hace falta para registrar también un hash del transcript (nunca el transcript ni la firma raw);
- verificar que ambos transcript hashes difieren y los fingerprints (r, nonce) coinciden.

No usar el test de 10,240 + 1,024 handshakes como sustituto: ese test mide unicidad en forward execution, no rollback.

## 6. Controles negativos

| Control | Resultado esperado |
|---|---|
| Dos VMs boot independientes | Nonce fingerprints diferentes |
| Disk-only snapshot/overlay | No duplicación de RAM pool demostrada; no debe contarse como rollback test |
| Fresh reboot antes de cada handshake | Pool nuevo; no afirmar nonce reuse |
| Snapshot full-state después de consumir el slot | Las ramas consumen el siguiente slot clonado, no el ya usado |
| Dos ramas con mismo transcript | No sirve para demostrar nonce reuse con mensajes distintos |
| Dos ramas con transcript distinto y fingerprint distinto | No hay evidencia de reuse para el slot probado |

## 7. Criterio de PASS/FAIL

**PASS — rollback nonce reuse demostrado:**
- ambas ramas reanudan el mismo full-state snapshot;
- el parser confirma el mismo slot pendiente antes de fork;
- ambas firmas verifican;
- transcript hashes son distintos;
- los fingerprints de (r, nonce) coinciden;
- la ecuación ECDSA recupera exclusivamente la clave sintética y se verifica contra su public key.

**PASS — no duplicación en el escenario probado:**
- ambas ramas reanudan correctamente;
- los transcript hashes son distintos;
- los nonces efectivos son distintos;
- el parser confirma que se consumieron los slots/CPU esperados.

**HARNESS_ERROR / NOT-TESTED:**
- no se puede restaurar el migration stream;
- BSS/POOLN no puede identificarse con certeza;
- los guests usan distintos vCPU/pool sin instrumentación;
- una firma no se verifica;
- el transcript hash no puede diferenciarse;
- se usa disk snapshot en lugar de full VM state.

No convertir un HARNESS_ERROR en evidencia de que el riesgo es imposible.

## 8. Riesgo y límites

Incluso si se demuestra nonce reuse entre clones, todavía hay que probar el modelo de despliegue:
- el servicio real debe ejecutarse en un entorno con full-RAM snapshot/fork;
- debe existir una ventana con POOLN > 0;
- dos ramas deben exponer firmas bajo la misma clave;
- el operador o infraestructura debe poder restaurar/forkear esa memoria.

El test local demuestra una propiedad del software bajo un modelo de snapshot, no que el bounty host use esa operación ni que un atacante remoto pueda activarla.

## 9. Estado

- Source-level precondition: CONFIRMED.
- Guest RAM scan / Montgomery scalar representation: CONFIRMED, pero no inspecciona POOLN ni restaura.
- Forward nonce uniqueness 10,240 + 1,024: CONFIRMED, pero no prueba rollback.
- Full-state migration/fork/restore: NOT-RUN.
- Duplicate nonce across two restored branches: NOT-TESTED.
- Production exposure: NOT ESTABLISHED.

**Resultado:** protocolo de experimento v0.1 preparado; no se ejecutó QEMU ni se modificó el código del bounty.
