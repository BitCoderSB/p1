# Fuente del agente

Esta carpeta contiene exactamente la fuente usada para construir los binarios
distribuidos en `.devtools/bin`.

- Requiere Go 1.24 o posterior compatible.
- Las releases de este repositorio exigen exactamente Go 1.24.13.
- El módulo no tiene dependencias externas.
- `go test ./...` ejecuta la suite.
- `scripts/build-agent.ps1` produce los seis targets con `CGO_ENABLED=0`,
  `-trimpath` y el digest de fuente embebido.

Ejemplo desde esta carpeta:

```powershell
go test ./...
.\scripts\build-agent.ps1 -OutputRoot ..\bin-staging-a -Version v0.2.6
.\scripts\build-agent.ps1 -OutputRoot ..\bin-staging-b -Version v0.2.6
```

El manifiesto `SHA256SUMS` se regenera después de construir y se verifica en
cada ejecución del lanzador. El build exige un staging nuevo y rechaza construir
dentro de `.devtools/bin`. Después de comparar dos builds reproducibles:

```powershell
.\scripts\promote-agent.ps1 `
  -StagingRoot ..\bin-staging-a `
  -Version v0.2.6 `
  -SourceDigest <digest-del-build> `
  -SessionsStopped
```

La promoción valida el conjunto exacto, verifica cada copia y publica el
manifiesto al final. Las sesiones de IA y procesos de hooks deben estar
detenidos durante esa operación.
