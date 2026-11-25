# K15 — ClientHello truncation and record-prefix matrix v0.1

- **Fecha:** 2026-11-25
- **Estado:** diseño de cobertura; NOT-RUN.
- **Objetivo:** ampliar la evidencia de framing TLS sin convertir offsets no probados en findings.
- **Restricción:** solo guests QEMU/TAP locales y credenciales sintéticas; nunca 15kb.org ni credenciales de producción.

## 1. Evidencia ya cerrada

El follow-up transcript-faithful [framing-handshake-followup.md](framing-handshake-followup.md) y el run [45460246415](https://github.com/miSultanato/k15/actions/runs/45460246415) ya demuestran:

- Frozen bounty: inner-short y outer-short completan TLS 1.3, verifican CertificateVerify/Finished, envían client Finished y obtienen HTTP 200.
- First upstream fix y current upstream: ambos variantes reciben fatal decode_error (2,50) antes de ServerHello.
- El caso outer-short usa el primer byte fuera del record como content-type 0x17 del siguiente record y no duplica ese byte.
- El cliente purpose-built construye el ClientHello malformado antes de calcular transcript hash; OpenSSL MemoryBIO mutado después no es suficiente.
- El HRR path normal ya se probó en run 45460246415 y el segundo ClientHello fue observado en ambas direcciones.

Esta matriz amplía offsets; no invalida ni reemplaza los resultados anteriores.

## 2. Reglas del transcript oracle

Para cada vector:
1. Construir los bytes malformados antes del transcript hash.
2. Determinar exactamente qué bytes pertenecen al primer TLS record según su longitud declarada.
3. Hash del ClientHello/handshake solo con los bytes que el server incorpora al transcript.
4. Colocar el prefijo del siguiente record en el stream TCP sin duplicar ni perder bytes.
5. Verificar CertificateVerify y server Finished contra el transcript exacto.
6. Enviar un client Finished correctamente cifrado y una petición HTTP.
7. En fixed images, exigir fatal decode_error; en frozen, exigir handshake completo y HTTP 200.
8. Si solo hay ServerHello, encrypted flight o timeout, no declarar full-handshake acceptance.

## 3. Inner handshake length matrix

Usar el mismo ClientHello base y variar únicamente el uint24 de longitud interna:

| ID | Longitud declarada | Propósito |
|---|---|---|
| CH-I00 | 0 | Longitud vacía |
| CH-I01 | 1 | Mínimo no válido |
| CH-I04 | 4 | Menor que handshake header |
| CH-I-M1 | body length − 1 | Truncado un byte (ya probado; control) |
| CH-I-EXACT | body length | Control válido |
| CH-I-P1 | body length + 1 | Un byte más que el contenido real |
| CH-I-P4 | body length + 4 | Cuatro bytes más |
| CH-I-MAX | 0xFFFFFF | Longitud máxima uint24 |

No asumir que todas las longitudes malformadas tienen el mismo resultado; registrar etapa y alerta.

## 4. Outer record length / next-record prefix matrix

El TLS record header declara fragment length. Variar cuánto se recorta del ClientHello record y alinear el siguiente record:

| ID | Recorte de fragment length | Bytes del siguiente record que pasan a quedar fuera del primer record |
|---|---:|---|
| CH-O1 | 1 | content-type |
| CH-O2 | 2 | content-type + primer byte de legacy_version |
| CH-O3 | 3 | content-type + legacy_version |
| CH-O4 | 4 | content-type + legacy_version + primer byte de length |
| CH-O5 | 5 | header completo del siguiente record |
| CH-O8 | 8 | header + 3 bytes de fragment |
| CH-O16 | 16 | header + 11 bytes de fragment |

El vector debe conservar el stream TCP byte-for-byte como dos records consecutivos. No insertar un segundo content-type ni duplicar los bytes ya usados como prefijo. Los casos CH-O2..O16 son nuevos; CH-O1 es el control ya validado.

## 5. Record-prefix alignment controls

Para cada recorte, variar el siguiente record entre:
- client Finished TLSCiphertext;
- un record TLSCiphertext válido con payload mínimo;
- un segundo handshake record solo cuando el flujo de protocolo lo permita.

Comprobar:
- primer byte 0x17;
- legacy_record_version 0x0303;
- length de record correcto;
- no solapamiento entre el fragment restante del ClientHello y el header del siguiente record;
- transcript hash calculado con los bytes del primer record, no con los bytes que el parser ya atribuyó al siguiente.

Un caso que solo funciona porque el harness duplica/omite bytes es inválido y debe rechazarse como HARNESS_ERROR.

## 6. Differential expectations

| Revisión | Resultado de control esperado |
|---|---|
| Frozen bounty ab93479 | Replicar inner-short/outer-short; los offsets nuevos quedan NOT-TESTED hasta ejecución |
| First upstream fix a2d8893 | Rechazo fatal decode_error de variantes fuera de framing permitido |
| Current upstream cb9f76a | Mismo rechazo que first fix |

No extrapolar el resultado de inner-short/outer-short a todos los offsets. Cada vector nuevo necesita evidencia independiente.

## 7. Seguridad y límites

- No ejecutar against 15kb.org ni otro endpoint público.
- No usar certificados, claves o tráfico de producción.
- No ejecutar fuzzing de carga ni loops de DoS.
- Mantener outputs/capturas dentro del entorno temporal; no subir certificados, claves, imágenes o captures privadas.
- No cambiar la rama bounty ni mezclarla con upstream fixes.
- No inferir private-key disclosure, RCE, memory corruption o recuperación de scalar a partir de una diferencia de framing.

## 8. Estado

La evidencia de inner-short/outer-short y HRR está cerrada en los runs citados. Esta matriz de offsets y alineación queda **NOT-RUN**. Es una expansión de cobertura, no un finding confirmado.
