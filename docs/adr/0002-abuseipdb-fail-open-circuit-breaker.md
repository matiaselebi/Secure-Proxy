# ADR 0002: Fail-open + circuit breaker para la consulta a AbuseIPDB

## Estado

Aceptado.

## Contexto

AbuseIPDB es un servicio externo con cupo limitado (1000 consultas/día en
el plan gratuito) y sin garantía de disponibilidad. El proxy necesita
decidir qué hacer con cada conexión mientras esa consulta está en curso, y
qué hacer si la API falla o está caída.

## Decisión

Dos decisiones relacionadas:

1. **Fail-open**: si la API no responde, responde con error, o no hay API
   key configurada, `get_abuse_score()` devuelve 0 (sin evidencia de abuso)
   en vez de bloquear por defecto o de tumbar la conexión. Un proxy que
   corta todo el tráfico porque un servicio de terceros está caído es peor
   que uno que temporalmente pierde esa capa de filtrado puntual (las demás
   capas - blocklist de dominios, IPs de C2, TOR - siguen actuando igual).
2. **Circuit breaker**: si hay `FAILURE_THRESHOLD` (3) fallos consecutivos,
   el cliente deja de intentar la llamada de red por `RESET_TIMEOUT_SECONDS`
   (60s), devolviendo 0 de inmediato. Sin esto, una caída prolongada de
   AbuseIPDB significaría pagar el timeout completo (5s) en cada conexión
   nueva que pase por el proxy durante toda la caída.

## Consecuencias

El proxy se degrada con gracia ante una falla externa, en vez de fallar en
cascada. El costo es que durante una caída de AbuseIPDB (o durante el
período de enfriamiento del circuito) esa capa de reputación de IP
específicamente no aporta nada - explícito en el README como limitación
conocida, no oculto.
