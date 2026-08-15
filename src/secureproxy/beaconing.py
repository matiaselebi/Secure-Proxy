"""Lo único que solo puede contestar este proxy: el ritmo de una conexión.

POR QUÉ ESTO ES LA FASE 3 DEL PUNTO 8

Al proxy se le sacó todo lo que hacían otros: los feeds los baja Secure-Intel,
el firewall lo escribe SecureHIPS, la correlación la hace Detect. Lo que quedó
tiene que ser lo único que ninguna otra pieza puede dar, y es esto: **el
proceso que abrió la conexión, cuánto transfirió, y con qué ritmo.**

Pi-hole ve el nombre consultado y lo bloquea antes y mejor. Suricata ve los
paquetes. Ninguno de los dos sabe que fue `svchost.exe` el que abrió esa
conexión, ni que la repite cada 60 segundos con una precisión que ningún
humano tiene.

QUÉ ES EL BEACONING

Un programa comprometido necesita preguntarle a su servidor "¿hay órdenes?".
Como no sabe cuándo va a haberlas, pregunta seguido y a intervalos regulares.
Eso deja una firma que el contenido no deja: **la regularidad**.

Una persona navegando genera intervalos caóticos: 3 segundos, 47, 2, 300. Un
programa que consulta cada minuto genera 60, 60, 61, 59, 60. La diferencia no
está en QUÉ se transfiere (que puede ir cifrado y ser indistinguible) sino en
CUÁNDO.

CÓMO SE MIDE, Y POR QUÉ ASÍ

Con el **coeficiente de variación** de los intervalos: el desvío estándar
dividido por el promedio. Es una sola cuenta y tiene una propiedad que la hace
la correcta para esto: **no depende de la escala**. Un beacon de 60 segundos y
uno de 3600 dan el mismo número si son igual de regulares, y eso es
exactamente lo que se quiere, porque el período lo elige el atacante.

Un umbral fijo sobre el desvío no serviría: 5 segundos de desvío es muchísimo
para un beacon de 10 segundos y nada para uno de una hora.

LO QUE ESTO NO ES

No es una detección de malware. Hay cosas legítimas con ritmo perfecto: la
sincronización de un cliente de correo, un chequeo de actualizaciones, la
telemetría de una aplicación. Por eso el resultado dice **"esto tiene ritmo de
beacon"** y no "esto es malicioso", y por eso se muestra junto al proceso: el
ritmo solo no alcanza, el ritmo MÁS quién lo hace sí es una pregunta que se
puede contestar mirando una pantalla.

Y por eso también hace falta un mínimo de conexiones antes de decir nada: con
tres intervalos, cualquier cosa puede parecer regular por casualidad.
"""

import statistics

# Cuántas conexiones al mismo destino hacen falta antes de opinar. Con menos,
# la regularidad puede ser pura casualidad: dos conexiones dan un solo
# intervalo, y un solo intervalo es siempre "perfectamente regular".
MINIMO_DE_CONEXIONES = 8

# Coeficiente de variación por debajo del cual el ritmo es sospechosamente
# regular. 0.25 quiere decir que el desvío es menos de un cuarto del promedio.
#
# El número sale de lo que hace cada uno: navegando, los intervalos varían más
# que el propio promedio (coeficiente arriba de 1). Un programa que consulta a
# intervalo fijo, con el ruido normal de la red, queda bien por debajo de 0.2.
# 0.25 deja margen para redes lentas sin abrir la puerta al tráfico humano.
COEFICIENTE_SOSPECHOSO = 0.25

# Intervalo mínimo, en segundos. Por debajo de esto no es un beacon: es una
# página cargando sus veinte recursos, o un video pidiendo sus fragmentos.
INTERVALO_MINIMO = 20

# Y un máximo: más de seis horas entre conexiones no es un ritmo que se pueda
# afirmar con la ventana de historial que guarda este proxy.
INTERVALO_MAXIMO = 21600


def intervalos(marcas: list) -> list:
    """Los segundos entre una conexión y la siguiente."""
    ordenadas = sorted(float(m) for m in marcas if m)
    return [b - a for a, b in zip(ordenadas, ordenadas[1:]) if b > a]


def coeficiente_de_variacion(valores: list) -> float:
    """Desvío estándar sobre promedio. 0 es perfectamente regular.

    Se devuelve un número grande (y no un error) cuando no se puede calcular:
    un valor alto significa "irregular", que es la respuesta segura cuando no
    hay con qué opinar.
    """
    if len(valores) < 2:
        return 999.0
    promedio = statistics.fmean(valores)
    if promedio <= 0:
        return 999.0
    return statistics.pstdev(valores) / promedio


def evaluar(marcas: list, bytes_totales: int = 0, minimo: int = 0) -> dict:
    """¿Este destino tiene ritmo de beacon? Devuelve el análisis completo.

    Devuelve siempre un diccionario con `sospechoso` y `motivo`, incluso
    cuando la respuesta es que no: el motivo del "no" es lo que permite
    entender la pantalla en vez de confiar en ella.
    """
    minimo = minimo or MINIMO_DE_CONEXIONES
    lista = intervalos(marcas)
    if len(lista) + 1 < minimo:
        return {"sospechoso": False, "conexiones": len(marcas),
                "motivo": (f"hacen falta al menos {minimo} conexiones "
                           f"y hay {len(marcas)}")}

    promedio = statistics.fmean(lista)
    coeficiente = coeficiente_de_variacion(lista)

    if promedio < INTERVALO_MINIMO:
        return {"sospechoso": False, "conexiones": len(marcas),
                "promedio": promedio, "coeficiente": coeficiente,
                "motivo": (f"las conexiones están a {promedio:.0f} segundos: eso no "
                           "es un ritmo, es una página cargando sus recursos")}
    if promedio > INTERVALO_MAXIMO:
        return {"sospechoso": False, "conexiones": len(marcas),
                "promedio": promedio, "coeficiente": coeficiente,
                "motivo": ("los intervalos son demasiado largos para afirmar un "
                           "ritmo con el historial que guardo")}

    sospechoso = coeficiente <= COEFICIENTE_SOSPECHOSO
    if sospechoso:
        motivo = (f"{len(marcas)} conexiones cada {promedio:.0f} segundos, con una "
                  f"regularidad de {coeficiente:.2f} (menos de "
                  f"{COEFICIENTE_SOSPECHOSO}). Una persona navegando no genera "
                  "intervalos así de parejos; un programa preguntando "
                  "«¿hay órdenes?» sí.")
    else:
        motivo = (f"los intervalos varían demasiado (regularidad {coeficiente:.2f}) "
                  "como para llamarlo un ritmo")
    return {"sospechoso": sospechoso, "conexiones": len(marcas),
            "promedio": promedio, "coeficiente": coeficiente,
            "bytes": int(bytes_totales), "motivo": motivo}


def analizar(filas: list, minimo: int = 0) -> list:
    """De un historial de conexiones a la lista de destinos con ritmo.

    Cada fila necesita `host` (o `destino`), `timestamp` y opcionalmente
    `proceso` y bytes. Se agrupa por (proceso, destino) y no solo por destino,
    y eso es deliberado: dos programas distintos hablando con el mismo servidor
    son dos historias, y mezclarlos rompe justamente la regularidad que se
    está buscando.
    """
    grupos: dict = {}
    for fila in filas:
        destino = (fila.get("host") or fila.get("destino") or "").strip().lower()
        if not destino:
            continue
        proceso = (fila.get("proceso") or fila.get("process") or "").strip()
        clave = (proceso, destino)
        grupo = grupos.setdefault(clave, {"marcas": [], "bytes": 0})
        grupo["marcas"].append(fila.get("ts") or fila.get("timestamp") or 0)
        grupo["bytes"] += int(fila.get("bytes_out") or 0) + int(fila.get("bytes_in") or 0)

    salida = []
    for (proceso, destino), grupo in grupos.items():
        analisis = evaluar(grupo["marcas"], grupo["bytes"], minimo=minimo)
        if analisis["sospechoso"]:
            salida.append({"proceso": proceso, "destino": destino, **analisis})
    # Lo más regular primero: es lo que menos se parece a una persona.
    salida.sort(key=lambda a: a["coeficiente"])
    return salida
