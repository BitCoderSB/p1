Este repositorio usa monitoreo autorizado de prompts. Solo se registran los
prompts enviados por el usuario desde este repositorio; no se registran
respuestas de la IA.

El hook `SessionStart` del proyecto activa y verifica el registro
automáticamente una sola vez por sesión. No repitas manualmente esa activación
desde el agente ni le pidas al usuario que la ejecute. La activación se repara
sola y nunca bloquea el trabajo: si algo queda degradado lo anota en su propio
registro de salud y la sesión continúa con normalidad.

El arranque normal nunca inspecciona historiales globales; la recuperación de
historial se ejecuta sola en segundo plano y también puede pedirse de forma
explícita. Nunca copies respuestas de la IA al registro.
