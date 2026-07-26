# ADR 0003: Modo "audit" como alternativa a "enforce"

## Estado

Aceptado.

## Contexto

Agregar una regla nueva (una lista de dominios recién importada, o bajar el
umbral de AbuseIPDB) siempre corre el riesgo de bloquear algo legítimo sin
que el usuario se entere hasta que algo deja de funcionar. No había forma
de probar el efecto de una regla nueva sin aplicarla de una.

## Decisión

`FilterEngine` acepta un parámetro `mode` ("enforce" por defecto, o
"audit"). En modo audit, evalúa las reglas exactamente igual, pero cualquier
decisión que hubiera bloqueado se convierte en "dejar pasar, pero
registrar qué se hubiera bloqueado y por qué" (`FilterDecision.
would_have_blocked`). El log queda igual de completo; el tráfico no se
corta.

## Consecuencias

Permite validar reglas nuevas mirando el dashboard/logs durante un rato
antes de pasar a "enforce" con confianza. El costo es que en modo audit el
proxy no protege de nada realmente - es un modo explícitamente para
pruebas, documentado como tal en el README y en el propio config.yaml, no
pensado para dejarlo activo en uso normal.
