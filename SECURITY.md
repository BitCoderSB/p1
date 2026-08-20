# Seguridad y privacidad

## Modelo de confianza

Los hashes incluidos junto a los binarios detectan corrupción accidental y
reemplazos parciales. No son una firma: una persona capaz de modificar el
binario y `SHA256SUMS` puede sustituir ambos. Un despliegue resistente a
manipulación debe distribuir binarios firmados y fijar su identidad desde una
política administrada fuera del repositorio.

La fuente exacta y reproducible está en `.devtools/src`; `version` muestra el
digest embebido. El lanzador rechaza un binario que no coincida con el
manifiesto y `bootstrap` revalida el hook Git, los tres hooks de captura, sus
wrappers y las instrucciones prompt-only. El manifiesto debe contener
exactamente seis rutas únicas; la promoción verifica los seis destinos y
reemplaza el manifiesto al final.

`bootstrap` **restaura** la configuración de captura que encuentra alterada, en
lugar de negarse a continuar. Detener la sesión nunca restablecía la captura:
solo impedía trabajar mientras los prompts se seguían perdiendo, y bastaba un
ajuste rutinario de VS Code o un archivo de metadatos del sistema operativo para
provocarlo. Lo que no se puede reparar —bytes de wrapper alterados, un archivo
de la persona que no se puede interpretar— queda anotado en `health.log` y se
reporta en `status`, que es el canal que la empresa sí observa. Esto detecta
manipulación; no la impide, igual que los hashes del manifiesto.

El almacén local tampoco es una frontera contra el propietario del equipo. Para
evaluaciones con requisitos de integridad, el registro autoritativo debe estar
en un servicio corporativo autenticado.

## Minimización

- Aceptar solo payloads de eventos oficiales de prompt.
- Usar una lista permitida de campos.
- No leer conversación desde el `transcript_path` recibido por un hook. La
  captura directa de Codex usa solo los campos documentados del evento; los
  historiales bajo `CODEX_HOME/sessions` se inspeccionan únicamente por el
  scanner secundario de recuperación.
- No capturar respuestas, tool results ni contenido de archivos.
- Aplicar redacción antes de persistir o transmitir.
- Limitar el tamaño de cada entrada y usar escritura atómica o append con
  sincronización a disco.
- Vincular cada payload directo con la raíz canónica del repositorio que
  ejecutó el wrapper y validar herramienta, usuario y proyecto al republicar.
- Rechazar symlinks en wrappers, hooks y rutas de almacenamiento; verificar que
  el archivo abierto sea el mismo archivo regular previamente inspeccionado.

Los scanners de recuperación sí inspeccionan historiales locales conocidos de
los proveedores. Clasifican por tipo de evento y solo convierten mensajes
humanos del repositorio actual al contrato `Event`. El parser del almacén usa
`DisallowUnknownFields`; una fila con campos de respuesta no se copia a
cuarentena: se conserva únicamente su SHA-256 y se reconstruye el registry.

La redacción automática reduce exposición accidental, pero no sustituye una
política que prohíba introducir secretos en prompts.

## Acceso y retención

Los registros contienen información laboral sensible. El repositorio remoto y
el backend deben aplicar mínimo privilegio, autenticación, trazabilidad de
consultas y cifrado en tránsito y reposo.

Los reportes HTML también contienen prompts. Se generan mediante reemplazo
atómico, con permisos privados, y no deben publicarse como artefactos abiertos.

No use Git como almacén de producción si debe garantizar borrado después de un
plazo: eliminar una línea del archivo actual no la elimina del historial,
forks, clones o respaldos. La retención debe aplicarse en un backend diseñado
para ello.

En modo local, el monitoreo de `pre-commit` es silencioso y *fail-open*:
reconstruye el registry público desde el respaldo privado y lo prepara dentro
del mismo commit, pero descarta su salida y siempre permite que Git continúe.
Abandona un lock de publicación ocupado después de 500 ms y nunca inspecciona
historiales de proveedores. Publicar aquí, y no en cada prompt, es lo que
mantiene limpio el árbol de trabajo de la persona: un archivo versionado que
cambia con cada prompt hace que `git pull --rebase`, `git switch` y `git merge`
se nieguen a ejecutarse. La entrega tampoco se condiciona al estado de los
archivos de hooks: un prompt ya durable pertenece a la empresa y se publica
aunque la configuración esté degradada.
El staging escribe blobs sin filtros, elimina
`assume-unchanged`/`skip-worktree` y verifica bytes, modo, OID y conjunto
completo cuando puede completarse. Un fallo puede dejar prompts únicamente en
el respaldo privado hasta un reintento posterior. Un hook ajeno no se modifica
automáticamente; el administrador debe componerlo de forma explícita.

La recuperación desde historiales corre en un proceso desacoplado, como máximo
una vez cada cinco minutos, disparada por la captura y por `SessionStart`; el
comando `recover` fuerza una pasada. En ambos casos importa exclusivamente
mensajes humanos del repositorio actual y escribe solo en el respaldo privado.
Es la única red de seguridad cuando un hook directo no llega a ejecutarse:
Codex exige aprobar cada definición de hook, y Claude y Copilot admiten
banderas que omiten los hooks del proyecto.

La recuperación se pagina en lotes de hasta 10 000 prompts o 64 MiB. El cursor
se guarda después del append durable y autentica mediante SHA-256 el prefijo
completo que ya fue procesado; no se acepta un cursor cuya línea pendiente no
exista. Por ello, un cierre entre el append y el cursor puede producir un
reintento deduplicable, pero no adelanta el cursor ni omite silenciosamente el
lote. Los wrappers esperan a que un `recover` pedido explícitamente termine en
lugar de matar el proceso con un timeout externo: esa orden puede tardar con un
historial grande, pero un recorrido finito puede alcanzar el append, `fsync` y
guardado de cursores. `pre-commit` nunca ejecuta `recover` ni la reconciliación
del respaldo privado; solo intenta preparar las copias públicas directas y
siempre conserva el resultado original del commit.

Los transcripts y respaldos se autentican desde handles estables: la
decodificación y el digest pertenecen a la misma vista de bytes, y antes de
confirmar el estado se valida en una sola pasada que cada respaldo usado siga
siendo un prefijo exacto. La deduplicación previa al presupuesto reserva IDs
exactos en todo el proveedor y también los observa en el snapshot que realmente
se importa. Una migración de ID queda vinculada uno-a-uno a su evento durable;
si ese objetivo aparece después como exacto, se invalida el progreso y se
rescanea en vez de omitir el otro prompt.

Cuando el archivo autoritativo está ocupado, el prompt se escribe en un archivo
propio bajo `.devtools/local-store/pending/`, que no requiere lock, y se integra
en la siguiente activación, recuperación o commit. Sin esa cola, una condición
transitoria —otro proceso sosteniendo el lock, un antivirus con el archivo
abierto— hacía que la captura terminara con código distinto de cero y el
proveedor rechazara el prompt de la persona.

## Señales que deben alertarse

- checksum inválido;
- hook no cargado o no confiado;
- error de escritura, bloqueo o disco lleno;
- proceso de captura excediendo su timeout;
- cola sin entrega durante el umbral acordado;
- una herramienta habilitada sin prompts, o cuyo último prompt es viejo mientras
  las otras están al día: es la firma de un hook que nunca se ejecutó, y `status`
  lo muestra por herramienta;
- reparaciones repetidas de la configuración de captura;
- secuencias de sesiones sin prompts;
- cambios en hooks, binarios, configuración o reglas de redacción;
- corrupción reparada, cuarentenas o drift de transformación;
- errores de publicación o de preparación del registry.

`health.log` guarda únicamente mensajes operativos genéricos. No debe contener
el prompt ni credenciales.
