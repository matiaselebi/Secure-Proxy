# ADR 0006: Filtro de ruido del panel, separado del filtrado de tráfico

## Estado

Aceptado.

## Contexto

El proxy del sistema ve todas las conexiones de la máquina, y buena parte
son ruido de fondo previsible: comprobaciones de "¿hay internet?",
validación de certificados en cada conexión TLS, chequeos de actualización,
telemetría. En una máquina real, el Top 10 de destinos eran diez dominios de
ese tipo y no se veía si había aparecido algo raro. Con la telemetría de
Google bloqueada a mano, además, el historial de bloqueos era la misma línea
repetida cientos de veces.

O sea: el panel estaba técnicamente bien y prácticamente inservible para lo
único que importa, que es notar lo anómalo.

La tentación obvia es resolverlo del lado del filtrado (no registrar esas
conexiones, o excluirlas del log). Eso sería un error: son datos de
seguridad, y un día podrían ser justamente la evidencia que se necesita.

## Decisión

Un filtro de **vista**, explícitamente separado del filtrado de tráfico, en
su propio módulo (`view_prefs.py`) y su propia sección del `config.yaml`
(`dashboard:`, no `filtering:`). La separación física es a propósito:
mezclarlos es como termina un panel de seguridad escondiendo justo lo que
tenía que mostrar.

Tres reglas lo hacen honesto:

1. No cambia nada de lo que se guarda ni de lo que se bloquea. Un dominio
   que está en la lista de ruido y además en la blocklist se sigue
   bloqueando igual.
2. El panel dice siempre cuántas conexiones está ocultando, arriba de todo.
3. Buscar un dominio ignora el filtro, con la misma lógica que el filtro de
   "solo bloqueadas": si lo estás auditando, lo querés ver entero.

Se apaga con un botón, sin reiniciar.

La lista que viene de fábrica (`data/noisy_domains.txt`) cubre el ruido de
SISTEMA. El ruido de cada máquina es distinto y no puede venir en ninguna
lista genérica: con Docker Desktop abierto todo el día,
`desktop.docker.com` se come el primer puesto del Top 10. Por eso la lista
se edita desde el panel, de un clic desde Consultar o escribiendo el
dominio en Configuración, donde además se ve entera. Sin eso, la
funcionalidad resolvía la mitad del problema.

## Implementación: por qué una columna y no una comparación por consulta

La primera versión comparaba el host contra los ~50 dominios de la lista en
cada consulta, con `host = ? OR host LIKE ?` por dominio. Funcionaba y era
simple, pero medido sobre 200.000 filas resultó en 100 comparaciones por
fila recorriendo la tabla entera: un refresco del panel pasó de
milisegundos a **3 segundos**, y el panel se refresca solo.

La versión que quedó marca cada conexión al registrarla, en una columna
`noisy` indexada. El filtro es un `WHERE noisy = 0` y el mismo refresco
tarda 335 ms, que es lo que ya costaban las agregaciones por sí solas.

La marca se escribe SIEMPRE, esté el filtro encendido o no. Eso es lo que
hace que prender y apagar el botón sea instantáneo: no hay nada que
recalcular. Y al arrancar, el proxy recorre el historial existente y
recalcula la marca (`remarcar_ruido`), así una base anterior al filtro, o
una lista editada a mano, quedan consistentes desde el primer refresco. Ese
recálculo es barato porque la cantidad de hosts DISTINTOS es de cientos: el
matcheo se hace en Python sobre esa lista chica y el UPDATE va por igualdad
de host, apoyado en su índice.

## Consecuencias

El panel vuelve a servir para lo que es: lo que queda a la vista es lo
inusual. El costo es una columna más, un índice más y un recálculo de menos
de un segundo al arrancar.

El riesgo real a vigilar es que alguien agregue a la lista un dominio que
después resulta relevante para una investigación. Se mitiga con las tres
reglas de arriba (el dato nunca se borra, el ocultamiento se anuncia, la
búsqueda lo ignora) y con el encabezado del propio archivo, que dice
explícitamente que un dominio sospechoso que aparece muchas veces NO va ahí:
eso es justamente lo que se quiere ver.
