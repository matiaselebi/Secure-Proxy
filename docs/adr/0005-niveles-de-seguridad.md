# ADR 0005: Niveles de seguridad en vez de opciones sueltas

## Estado

Aceptado.

## Contexto

Con la Fase 2, el motor pasó a tener cuatro perillas que interactúan entre
sí: el umbral de AbuseIPDB, el chequeo de nodos TOR, el modo lista blanca y
el modo enforce/audit. Pedirle a alguien que las combine bien es pedirle que
entienda las consecuencias de cada cruce. En particular hay una combinación
peligrosa: activar el modo lista blanca en enforce deja la máquina sin
internet en el primer minuto, porque no hay lista escrita a mano que cubra
el navegador, el sistema operativo y cada aplicación.

## Decisión

Tres niveles con nombre, que fijan las cuatro opciones juntas:

| Nivel | AbuseIPDB | TOR | Dominios desconocidos | Modo |
|---|---|---|---|---|
| Normal | 50 | bloquea | permite | enforce |
| Estricto | 25 | bloquea | permite | enforce |
| Paranoico | 10 | bloquea | marca como sospechosos | **audit** |

Aplicar un nivel escribe todas sus opciones en `config/config.yaml` y las
aplica en caliente, sin reiniciar.

El punto importante de la tabla es la última fila: Paranoico va en audit **a
propósito**, no por omisión. No es "Estricto pero más": es un modo de
diagnóstico para descubrir qué política de lista blanca tendrías que armar,
mirando el historial. La combinación peligrosa directamente no se puede
elegir desde el panel.

Las opciones sueltas siguen existiendo en la pestaña Configuración. Si se
toca una, `security_level` deja de coincidir con lo aplicado y el panel
muestra "personalizado" en vez de mentir diciendo que seguís en Normal.

## Consecuencias

Un usuario que no quiere pensar tiene un default correcto y dos escalones
claros. Uno que sí quiere pensar no pierde nada: las perillas siguen ahí, y
el panel es honesto sobre cuándo dejó de estar en un nivel conocido.

El costo es que hay dos formas de configurar lo mismo, y `_nivel_actual()`
tiene que comparar el estado real del motor contra cada nivel para saber si
todavía coincide con alguno. Eso está cubierto por tests.
