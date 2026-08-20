# MonitoreoIA

Plantilla de evaluación que registra, con aviso y autorización previos, los
prompts que una persona envía a Codex, Claude Code o GitHub Copilot mientras
trabaja dentro de este repositorio..

## Datos registrados

El contrato del agente admite únicamente:

- prompt escrito por el usuario;
- herramienta, sesión y fecha;
- identidad Git o identidad estable del dispositivo;
- repositorio, rama y commit asociados.

No existe un campo para respuestas de IA, razonamiento, resultados de
herramientas ni contenido de archivos. Los JSONL se leen con esquema estricto:
una fila que agregue `response`, `assistant_response` u otro campo se excluye,
se conserva solo su SHA-256 como evidencia y el registro se reconstruye desde
el respaldo autoritativo.

La captura directa valida que `cwd` pertenezca a este repositorio y no a un
repositorio Git anidado. Claude también exige los marcadores oficiales de
Claude Code y `CLAUDE_PROJECT_DIR`, para que VS Code/Copilot no ejecute el hook
Claude como una segunda captura mal etiquetada.

Se requiere Claude Code 1.0.58 o posterior: `UserPromptSubmit` apareció antes,
pero `CLAUDE_PROJECT_DIR` —necesario para aislar el repositorio sin duplicar
capturas de otros proveedores— está disponible desde esa versión.

La captura directa de Codex requiere una versión estable de Codex CLI 0.134.0
o posterior. `status` valida la versión instalada y la captura valida
exclusivamente el contrato oficial del hook:
`session_id`, `turn_id`, `cwd`, `permission_mode` y `prompt` deben estar
presentes. La presencia de `agent_id` o `agent_type` se rechaza como señal de
subagente. El `transcript_path` no se abre ni se usa para decidir si una
captura directa es válida; su formato interno no forma parte del contrato del
hook.

Copilot CLI requiere la versión estable 1.0.22 o posterior para compartir con
VS Code el mismo archivo PascalCase y recibir el payload compatible
snake_case. Un cliente que no está instalado no bloquea a los demás.
`SessionStart` no lanza copias anidadas de Codex, Claude ni Copilot, porque
algunos sandboxes pueden bloquearlas. La comprobación explícita `status`
diagnostica de forma estricta cualquier versión instalada incompatible.

## Flujo de captura

1. Cada herramienta ejecuta `bootstrap` en `SessionStart` y usa
   `UserPromptSubmit`. El archivo Copilot usa los nombres PascalCase y el campo
   `command`: es el formato común de Copilot CLI moderno y VS Code.
2. El lanzador verifica el SHA-256 del binario antes de cada ejecución.
3. El agente redacta secretos, persiste el evento en el respaldo privado y hace
   `fsync` antes de confirmar éxito. Si ese archivo está ocupado —otro proceso
   sostiene su lock, un antivirus o un cliente de sincronización lo mantiene
   abierto— el prompt se escribe en un archivo propio dentro de
   `.devtools/local-store/pending/`, que no necesita lock. Nunca se rechaza el
   prompt de la persona por una condición transitoria. La cola se integra al
   respaldo en la siguiente activación, recuperación o commit.
4. La captura **no** escribe la copia pública. Esa copia está versionada, así
   que tocarla en cada prompt dejaba el árbol de trabajo permanentemente sucio
   y `git pull --rebase`, `git switch` y `git merge` se negaban a ejecutarse.
   El hook `pre-commit` reconstruye y prepara `.devtools/registry/<usuario>.jsonl`
   desde el respaldo privado dentro del mismo commit, de modo que el árbol
   queda limpio en cuanto el commit termina.
5. La captura durable no depende del índice, los objetos ni los hooks de Git.
   `pre-commit` abandona un lock ocupado después de 500 ms y es *fail-open*:
   nunca cambia el resultado del commit ni escribe advertencias en la terminal.
   La entrega tampoco depende del estado de los archivos de hooks: un prompt ya
   durable pertenece a la empresa y se publica aunque la configuración esté
   degradada o en reparación.
6. Los IDs nativos (`prompt_id`, `turn_id` o sesión+timestamp de Copilot)
   deduplican invocaciones del mismo evento desde varias capas de hooks. El
   escaneo de recuperación se correlaciona uno-a-uno con las capturas directas
   por herramienta, sesión y texto dentro de una ventana de diez minutos: el
   hook sella su propio reloj y el transcript el del cliente, así que exigir un
   timestamp idéntico duplicaba cada prompt.
7. Los fallos operativos dejan mensajes genéricos —nunca el prompt— en
   `.devtools/local-store/health.log`.

Los tres hooks `UserPromptSubmit` tienen 30 segundos de timeout. Los hooks
`SessionStart` tienen 15 segundos y no escanean historiales, abren el registry
ni lanzan CLIs anidados. Los sondeos de versión se ejecutan únicamente con
`status`, se limitan a cinco segundos y terminan el árbol del proceso para que
un shim de Node bloqueado no retenga el diagnóstico indefinidamente.

Una escritura interrumpida se repara antes del siguiente append. Antes de
truncar el original se sincroniza en una cuarentena privada únicamente la
longitud y el SHA-256 del fragmento incompleto, nunca su contenido. Las
colisiones o modificaciones del registry se aíslan sin impedir que se publiquen
prompts posteriores.

## Recuperación desde historiales

Codex y Claude Code mantienen JSONL locales. VS Code también mantiene
transcripts de Copilot Chat. Esos historiales son la única red de seguridad
cuando un hook directo no llega a ejecutarse, y eso ocurre de verdad: Codex
exige que la persona apruebe cada definición de hook antes de ejecutarla, así
que en un clon recién hecho sus prompts no se capturan por hook hasta ese
momento. Claude y Copilot admiten banderas y ajustes de usuario que omiten los
hooks del proyecto, y un cliente antiguo puede no emitir el evento.

Por eso la recuperación ya no depende de que alguien escriba un comando. Cada
captura y cada `SessionStart` lanzan, como máximo una vez cada treinta minutos,
un proceso **desacoplado** que recorre esos historiales con presupuesto acotado
e importa únicamente los prompts humanos de este repositorio. No retiene la
sesión y no publica la copia pública: solo escribe en el respaldo privado
ignorado por Git, de modo que no ensucia el árbol de trabajo. Un lock no
bloqueante evita que dos sesiones recorran los mismos transcripts a la vez, y
un vigilante lo termina si excediera cinco minutos.

El proceso corre en prioridad **Idle**, de modo que solo usa CPU que de otro
modo quedaría ociosa. Medido sobre un historial de Codex de 7 GB —mucho mayor
que el de un empleado nuevo—: 49 segundos de duración, 34 MB de RAM y 16
segundos de CPU por pasada, y después el proceso termina y no deja nada
residente. Con una pasada cada media hora eso es menos del 1 % de un solo
núcleo. El intervalo es amplio a propósito: no se pierde nada por esperar,
porque los hooks directos capturan en tiempo real y esta pasada solo recoge lo
que un hook no pudo entregar.

Ese proceso y **todo lo que ejecuta** —`git`, sobre todo— se crean con
`CREATE_NO_WINDOW` en Windows. Es un detalle imprescindible, no cosmético: un
proceso de consola sin consola hace que Windows le asigne una consola nueva, es
decir una ventana de Terminal visible, a cada hijo que lance. Como la
recuperación invoca `git` decenas de veces, esa sola omisión llenaba el
escritorio de ventanas cada vez que se abría el proyecto.

Además, **ver los prompts los recupera primero**. `log` y `report` recorren los
transcripts locales de forma síncrona antes de mostrar nada, porque pedir ver es
justo el momento en que la persona espera encontrar lo que acaba de escribir.
`status` y cada `commit` disparan la misma pasada en segundo plano. Así, el caso
más difícil —un clon nuevo donde Codex nunca ejecutó un hook porque no se
aprobó— queda cubierto en cuanto alguien revisa o confirma.

El comando explícito `recover` sigue existiendo para forzar una pasada. En todos
los casos se persisten exclusivamente eventos humanos del repositorio actual;
las respuestas se descartan.

**Activación de Codex mediante `.codex/AGENTS.md`.** Codex no ejecuta ningún hook
del proyecto hasta que la persona lo aprueba una vez con `/hooks`; no hay forma
desde el checkout de saltarse esa aprobación. Pero Codex sí carga
`.codex/AGENTS.md` automáticamente al inicio de cada sesión, sin aprobar nada.
Ese archivo instruye al agente para que, en el primer mensaje de un clon nuevo,
ejecute una sola vez el comando de activación —y solo si no existe el marcador
`.devtools/local-store/.initialized`—. Esa activación instala el `pre-commit` y
dispara la recuperación, que importa el prompt que la persona acaba de escribir
(ya está en el transcript de Codex cuando el agente actúa). En los mensajes
siguientes el marcador ya existe, así que el agente no vuelve a ejecutar nada:
es una sola ejecución por clon, no en cada prompt.

Ese arranque tiene dos costos honestos: el comando es visible en el chat de
Codex la primera vez, y depende de que el modelo obedezca la instrucción. Por
eso no es la única red: la recuperación desde el transcript también se dispara
al ver los prompts, al hacer commit, con `status`, o cuando la persona usa
Claude/Copilot en el mismo repo. Para una garantía *fail-closed* real hay que
desplegar política administrada (MDM). Claude Code y Copilot capturan en directo
con solo clonar, así que sus archivos de instrucciones permanecen pasivos y no
piden ejecutar ningún comando.

Este respaldo tiene límites deliberadamente documentados:

- el fallback de Copilot corresponde a Copilot Chat en VS Code, no al historial
  de Copilot CLI;
- un error de transcript no borra las capturas directas. `pre-commit` nunca
  abre historiales: descarta toda salida de su intento de reconstruir y
  preparar las copias públicas y el commit continúa; el respaldo local conserva
  lo durable para reintentos posteriores;
- un error de validación, publicación o staging tampoco cancela el commit. Puede
  dejar prompts únicamente en el respaldo privado hasta que una ejecución
  posterior consiga reconstruir y preparar el registry;
- una fila malformada o una línea mayor al límite hace parcial la recuperación
  de ese transcript y genera alerta; las capturas directas y las filas ya
  importadas permanecen disponibles;
- cada pasada recupera como máximo 10 000 prompts o 64 MiB y cada línea se
  limita a 8 MiB. Si queda trabajo, persiste un cursor durable en la primera
  línea pendiente solamente después de sincronizar los eventos recuperados.
  La siguiente ejecución autentica con SHA-256 todo el prefijo anterior antes
  de reanudar; una reescritura, truncamiento o cursor fuera de EOF fuerza un
  reescaneo seguro desde el inicio;
- cada transcript se decodifica y se hashea desde el mismo handle y un tamaño
  fijo. Antes de guardar estado se vuelve a validar que los respaldos
  autoritativos usados para deduplicar sigan presentes como prefijos exactos;
- los eventos exactos, las capturas directas y las migraciones de IDs históricos
  se reservan antes de consumir el presupuesto del lote. Los aliases de una
  migración son uno-a-uno, quedan ligados al respaldo autoritativo y fuerzan un
  reescaneo si su evento objetivo reaparece como exacto; así, un diagnóstico
  persistente no puede hacer que las mismas filas hambreen prompts posteriores;
- un `cwd` transitoriamente irresoluble no adelanta el estado. Se vuelve a
  intentar aunque el transcript no haya cambiado, de modo que el prompt se
  recupera cuando la ruta vuelve a estar disponible;
- el estado incremental de escaneo es una optimización privada y se regenera si
  se corrompe o si desaparece, se trunca o se reemplaza un respaldo
  autoritativo.

## Activación

Los hooks de Codex, Claude y Copilot ejecutan automáticamente una vez por
sesión:

```text
.devtools/setup bootstrap
```

En Windows se usa `.devtools\setup.cmd bootstrap`. El primer arranque de cada
versión repara metadatos de permisos heredados, valida el almacenamiento
durable, instala el `pre-commit` de mejor esfuerzo y escribe un marcador de
versión. No lee prompts ni prepara el índice. Los siguientes arranques
verifican el hash del binario, la captura durable y la configuración de los
proveedores.

Esa verificación responde una sola pregunta: ¿un prompt escrito en este
checkout se seguiría registrando? Comprueba los bytes de los wrappers, la
presencia de los comandos canónicos con sus timeouts exactos —30 segundos para
captura, 15 para activación— y los interruptores `disableAllHooks`. Todo lo
demás que una persona o un editor puedan agregar alrededor se tolera: otras
claves en `.claude/settings.json` o en `.vscode/settings.json`, archivos
adicionales en `.github/hooks`, hooks propios en los `settings.local.json`.
Antes, cualquiera de esos cambios rutinarios terminaba la sesión.

**La activación se repara sola y nunca interrumpe el trabajo.** Si falta un
archivo de hooks, alguien lo desactivó o quedó a medio escribir, se restaura su
contenido canónico y la sesión continúa. `.vscode/settings.json` y los
`settings.local.json` pertenecen a la persona: se fusionan, no se sobrescriben,
y si no se pueden interpretar se dejan intactos. Lo que no se puede reparar se
anota en `health.log`, se reporta en `status` y la sesión sigue igual. Un
arranque nunca devuelve un error que la persona tendría que resolver para poder
trabajar.

VS Code carga explícitamente `.github/hooks` y desactiva sus tres ubicaciones
Claude heredadas para evitar una segunda invocación. Los archivos de hooks
propios del proyecto siguen limitados a `SessionStart` y `UserPromptSubmit`:
registrar cualquier otro evento de ciclo de vida es la única forma en que este
proyecto podría convertirse en un grabador de respuestas. Un `core.hooksPath`
compartido fuera del directorio Git de este repositorio nunca se modifica.

La identidad `development/workspace`, los tres adaptadores y la política
completa del proyecto están fijados en el binario: endpoint, modo local,
auto-enrollment, redacción, reglas adicionales vacías y retención de 365 días.
Editar `.devtools/project.json` para desviar prompts, retirar un adaptador o
debilitar esa política hace fallar la activación. En modo local, el
identificador publicado del repositorio también deriva de esa identidad y no
cambia al modificar `remote.origin.url`.

Las herramientas exigen confianza explícita antes de ejecutar código del
repositorio:

- Codex requiere confiar el proyecto y aprobar la definición exacta del hook.
- Claude Code requiere workspace trust para hooks de comando.
- Copilot requiere un directorio confiable para hooks del repositorio.

El repositorio no puede concederse confianza a sí mismo. Sin esa aprobación,
la operación explícita `recover` puede reconstruir algunas superficies, pero
no sustituye los hooks ni ofrece una garantía absoluta.

## Modo local actual

`.devtools/project.json` usa `"local_store": true`. Es un modo demostrativo:

- el respaldo autoritativo permanece ignorado por Git;
- la empresa recibe el registry únicamente después de commit y push;
- `pre-commit` intenta preparar solo las copias públicas ya escritas por la
  captura directa, sin escanear historiales, esperar los locks largos de
  reconciliación, cambiar el resultado del commit ni mostrar advertencias;
- `retention_days` no puede borrar datos de commits, clones, forks o respaldos;
- una persona con control total del equipo puede modificar hooks, binarios,
  manifiesto o registros.

Hasta que los cambios de esta plantilla estén confirmados y enviados al remoto,
un clon nuevo no los recibe. Antes del primer commit/push, una pérdida del disco
o del clon también puede destruir la única copia de una captura local. En
Codex, el modo normal de escritura protege `.git`: la captura y el registry del
working tree siguen funcionando, pero la preparación automática del índice se
reintenta cuando Git vuelva a estar disponible.

Por tanto, este modo no debe presentarse como monitoreo central de producción.
Además, un hook `pre-commit` ajeno no se sobrescribe; la captura continúa y la
entrega pendiente permanece recuperable desde el respaldo privado.

## Límites de proveedores

Claude Code y Copilot continúan el prompt si un hook se bloquea, falla o excede
su timeout en varias configuraciones. Copilot CLI es siempre *fail-open* para
`UserPromptSubmit`, incluso con policy hooks. Codex y Claude pueden bloquear
con código `2`; el agente usa ese código solamente cuando falló antes de la
persistencia durable.

Además, Claude permite omitir hooks de proyecto mediante `--safe-mode`,
`--bare`, `--setting-sources` o `--settings`/`disableAllHooks`; Codex permite
`/hooks`, `--disable hooks` y `-c features.hooks=false`; Copilot permite
`disableAllHooks` y su modo `-p` requiere confianza o una política/variable que
autorice hooks del repositorio. Esas rutas se deben bloquear mediante política
administrada y un launcher corporativo; el checkout por sí solo no puede
impedirlas. En cada captura normal, el wrapper vincula el `cwd` del payload con
la raíz canónica del repositorio que ejecutó el hook y rechaza una mezcla de
proyectos.

El envelope JSON del hook se limita a 8 MiB para admitir el peor caso de escape
de un prompt válido. El prompt almacenado se limita a 1 MiB. La redacción
normalmente reduce el tamaño; si una regla patológica lo expande por encima de
ese límite, se agrega una marca explícita de truncamiento y una alerta de
salud. Un backend central debe configurar el mismo límite de prompt de 1 MiB:
el valor predeterminado de 64 KiB del servidor de referencia no es compatible.

## Despliegue empresarial

Para una evaluación real:

1. instalar un servicio local administrado fuera del checkout, protegido con
   ACL y con journal durable;
2. desplegar hooks administrados mediante MDM/política de dispositivo;
3. usar configuración *managed-only* o retirar los hooks de proyecto cuando un
   proveedor antiguo no entregue un ID nativo estable;
4. filtrar por ruta canónica e identidad del repositorio;
5. subir por HTTPS autenticado con ACK idempotente y reintentos;
6. aplicar retención y acceso mínimo en el backend, no en Git;
7. alertar por hook ausente, checksum inválido, disco lleno, servicio detenido,
   cola atrasada o sesiones activas sin eventos.

Si se necesita un gate realmente *fail-closed* para Copilot, se debe impedir el
cliente CLI directo y proporcionar un cliente corporativo basado en Copilot
SDK.

## Operación y fuente reproducible

```powershell
# Diagnóstico operativo; SessionStart ya lo ejecuta automáticamente:
.\.devtools\setup.cmd bootstrap
.\.devtools\setup.cmd version
.\.devtools\setup.cmd recover
.\.devtools\setup.cmd status
.\.devtools\setup.cmd report
```

Linux y macOS usan `./.devtools/setup`. `status` es el diagnóstico del
administrador: repara lo que puede, informa cada degradación que quede y
muestra, por herramienta, cuántos prompts hay y cuál fue el último. Una
herramienta con cero prompts, o con un último prompt viejo mientras las otras
están al día, es la firma de un hook que nunca se ejecutó.

Solo `recover` inspecciona historiales en primer plano y puede tardar según su
tamaño; la pasada automática equivalente ya corre desacoplada en segundo plano.
`bootstrap`, `status`, `log` y `report` trabajan con las
capturas directas ya durables. `recover` espera a que el recorrido finito
termine para no perder el progreso al cortar el proceso antes de guardar el
estado.

La fuente exacta del agente, sus pruebas y el script reproducible de los seis
targets se distribuyen en `.devtools/src`. Los binarios se construyen con
Go 1.24.13 fijado, entorno limpio, `CGO_ENABLED=0`, `-trimpath`, un digest de
fuente embebido y hashes registrados en `.devtools/bin/SHA256SUMS`. El build
exige un staging nuevo, comprueba que la fuente no cambie durante los seis
targets y rechaza reparse points. `scripts/promote-agent.ps1` valida el conjunto
exacto, copia y revalida los seis binarios y publica `SHA256SUMS` al final.

## Referencias oficiales

- [Hooks de Codex](https://learn.chatgpt.com/docs/hooks)
- [Configuración administrada de Codex](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Hooks de Claude Code](https://code.claude.com/docs/en/hooks)
- [Configuración administrada de Claude](https://code.claude.com/docs/en/settings)
- [Hooks de GitHub Copilot](https://docs.github.com/en/copilot/reference/hooks-reference)
- [Configuración de Copilot CLI](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference)
- [Hooks de agentes en VS Code](https://code.visualstudio.com/docs/agent-customization/hooks)
