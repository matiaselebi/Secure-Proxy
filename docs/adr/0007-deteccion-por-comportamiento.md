# ADR 0007: Detección por comportamiento, además de por listas

## Estado

Aceptado.

## Contexto

Hasta acá todo lo que el proxy decidía salía de una lista: dominios de
URLhaus, IPs de Feodo, rangos de FireHOL, pools de minería, scores de
AbuseIPDB. Eso funciona bien y es barato, pero comparte una limitación de
fondo: **solo encuentra lo que alguien ya reportó**. Un dominio registrado
esta mañana, o un servidor de comando-y-control que nunca fue publicado, no
está en ninguna lista y pasa sin que nadie se entere.

El proxy, sin embargo, ya venía juntando datos que ninguna lista tiene:
cuándo se conectó cada cosa, y (desde esta ronda) cuánto movió y desde qué
proceso. Sobre eso se pueden hacer preguntas que no dependen de que nadie
haya reportado nada.

## Decisión

Dos detectores que miran la **forma** del tráfico, no su reputación. Ninguno
bloquea: los dos señalan.

**Por volumen** (exfiltración). Se cuentan los bytes en cada dirección del
túnel y se muestra adónde se subió más. Lo subido y no lo bajado, porque
bajar mucho es ver un video. Esto no requiere descifrar nada: el contenido
de un túnel HTTPS es opaco, pero su tamaño y su dirección no.

**Por regularidad** (beaconing / C2). Se calculan los intervalos entre
conexiones consecutivas hacia un mismo destino y se mide su dispersión
relativa. Una persona navegando da valores altísimos; un programa
preguntando "¿hay órdenes nuevas?" da valores cerca de cero.

Esto es explícitamente distinto del detector de "destinos insistentes" que
ya existía. Aquel mide **cuánto** y con eso encuentra un minero, que
martilla el mismo pool miles de veces. Un implante de C2 hace lo contrario a
propósito, para no destacarse por volumen: se conecta poco, pero como un
reloj. Los dos detectores son necesarios porque buscan comportamientos
opuestos.

Como contexto para los dos, cada conexión se registra ahora con el proceso
que la abrió, resuelto por el puerto de origen contra la tabla de sockets
del sistema operativo (`GetExtendedTcpTable` en Windows, `/proc` en Linux),
sin dependencias nuevas y sin salir a la red.

## Consecuencias

Lo importante: **ninguno de los dos bloquea, y eso no es timidez, es
correcto**. Un cliente de correo revisando cada 60 segundos da exactamente
la misma firma de beaconing que un implante; un backup a la nube da la misma
firma de volumen que una exfiltración. Bloquear con esa señal sería romper
cosas legítimas todo el tiempo.

Lo que hace útil a la señal, entonces, es el proceso al lado: `outlook.exe`
cada 60 segundos es una cosa y `rundll32.exe` cada 60 segundos es otra. Por
eso el proceso no es un adorno del registro sino la pieza que convierte una
lista de "esto es raro" en algo accionable. Sin él, los dos detectores serían
generadores de falsos positivos.

El costo es que ambos detectores viven en el panel y requieren que alguien
los mire. Se compensa parcialmente con los avisos de escritorio, pero esos
solo cubren los bloqueos por lista, no estas señales: alertar por
comportamiento tendría demasiados falsos positivos como para no terminar
apagado.

Sobre el proceso hay una consecuencia operativa a tener presente: cuando el
proxy no corre como administrador, algunos procesos del sistema no se dejan
consultar y la fila queda sin ese dato. Se prefirió eso antes que exigir
permisos elevados para todo.
