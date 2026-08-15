"""Logging estructurado de cada request que pasa por el proxy, en SQLite."""

import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


class LoggerDB:
    """Wrapper simple y thread-safe sobre SQLite para loguear tráfico del proxy."""

    # Cada cuántas inserciones se revisa si hay que recortar el historial.
    PRUNE_EVERY = 500

    def __init__(self, db_path: str, max_rows: int = 200_000):
        self.db_path = db_path
        # Tope de filas del historial. 200.000 es holgado para mirar la
        # actividad reciente (son varios días de navegación normal) y deja
        # el archivo en el orden de decenas de MB, no de cientos.
        # `max_rows=0` desactiva el recorte.
        self.max_rows = max_rows
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._inserts_since_prune = 0
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        # check_same_thread=False porque el proxy es multi-thread y compartimos
        # una sola instancia de LoggerDB entre requests.
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_schema(self) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT,
                    method TEXT,
                    host TEXT,
                    port INTEGER,
                    path TEXT,
                    blocked INTEGER NOT NULL,
                    reason TEXT,
                    duration_ms REAL
                )
                """
            )
            # Índice sobre `blocked`: el dashboard cuenta las bloqueadas y
            # pide las últimas 25 en CADA refresco (cada 5 segundos). Sin
            # índice eso recorre la tabla entera cada vez; con cientos de
            # miles de filas la página tarda tanto que parece colgada. Con
            # índice es instantáneo sin importar cuánto haya crecido.
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_requests_blocked "
                "ON requests (blocked, id DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_requests_timestamp "
                "ON requests (timestamp)"
            )
            # Columnas agregadas después: se suman con ALTER TABLE en vez de
            # recrear la tabla, así una base que ya existe se actualiza sola
            # sin perder el historial. Las filas viejas quedan con estos
            # campos vacíos, que es la verdad: en ese momento no se guardaban.
            existentes = {
                fila[1] for fila in conn.execute("PRAGMA table_info(requests)")
            }
            for columna in ("dest_ip", "country", "asn", "provider"):
                if columna not in existentes:
                    conn.execute(f"ALTER TABLE requests ADD COLUMN {columna} TEXT")
            # Proceso que originó la conexión, y volumen en cada dirección.
            # Se suman por el mismo camino aditivo.
            if "process" not in existentes:
                conn.execute("ALTER TABLE requests ADD COLUMN process TEXT")
            for columna in ("bytes_out", "bytes_in"):
                if columna not in existentes:
                    conn.execute(
                        f"ALTER TABLE requests ADD COLUMN {columna} INTEGER NOT NULL DEFAULT 0"
                    )
            # Marca de "ruido" (telemetría, comprobación de internet,
            # actualizaciones). Se guarda como columna en vez de resolverse
            # en cada consulta por una razón medida: comparar el host contra
            # los ~50 dominios de la lista con LIKE obliga a recorrer la
            # tabla entera haciendo 100 comparaciones por fila, y con 200.000
            # filas un refresco del panel pasaba de milisegundos a 3
            # segundos. Marcada e indexada, el filtro vuelve a ser gratis.
            if "noisy" not in existentes:
                conn.execute(
                    "ALTER TABLE requests ADD COLUMN noisy INTEGER NOT NULL DEFAULT 0"
                )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_requests_noisy "
                "ON requests (noisy, id DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_requests_host ON requests (host)"
            )
            # Los ritmos detectados, guardados. Es la única tabla de este
            # archivo que no es un registro de lo que pasó sino una
            # CONCLUSIÓN, y existe por una razón concreta: SecureCenter lee
            # las bases de los proyectos, no les pide nada por la red. Si el
            # ritmo se calculara solo cuando alguien abre el panel, Detect no
            # tendría de dónde sacarlo, y la alternativa sería que SecureCenter
            # repitiera la cuenta. Repetirla es lo que el punto 8 vino a sacar.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ritmos (
                    proceso TEXT NOT NULL,
                    destino TEXT NOT NULL,
                    visto TEXT NOT NULL,
                    conexiones INTEGER NOT NULL,
                    promedio REAL NOT NULL,
                    coeficiente REAL NOT NULL,
                    bytes INTEGER NOT NULL DEFAULT 0,
                    motivo TEXT,
                    PRIMARY KEY (proceso, destino)
                )
                """
            )
            conn.commit()

    def log_request(
        self,
        client_ip: str,
        method: str,
        host: str,
        port: int,
        path: str,
        blocked: bool,
        reason: str = "",
        duration_ms: float = 0.0,
        dest_ip: str = "",
        country: str = "",
        asn: str = "",
        provider: str = "",
        noisy: bool = False,
        process: str = "",
        bytes_out: int = 0,
        bytes_in: int = 0,
    ) -> int:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                """
                INSERT INTO requests
                    (timestamp, client_ip, method, host, port, path, blocked,
                     reason, duration_ms, dest_ip, country, asn, provider, noisy,
                     process, bytes_out, bytes_in)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, client_ip, method, host, port, path, int(blocked),
                 reason, duration_ms, dest_ip, country, asn, provider, int(noisy),
                 process, int(bytes_out), int(bytes_in)),
            )
            fila_id = cur.lastrowid
            conn.commit()
        self._maybe_prune()
        # Se devuelve el id porque el volumen de un túnel HTTPS recién se
        # sabe cuando el túnel se cierra, que puede ser media hora después:
        # la fila se escribe al abrirlo y se completa al final.
        return fila_id

    def actualizar_volumen(self, fila_id: int, bytes_out: int, bytes_in: int) -> None:
        """Completa el volumen de una conexión ya registrada."""
        if not fila_id:
            return
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                "UPDATE requests SET bytes_out = ?, bytes_in = ? WHERE id = ?",
                (int(bytes_out), int(bytes_in), fila_id),
            )
            conn.commit()

    # ---------- retención ----------

    def _maybe_prune(self) -> None:
        """Cada tantas inserciones, recorta el historial al tope configurado.

        Un proxy que es el proxy del sistema ve TODAS las conexiones de la
        PC, así que el log crece rápido y para siempre. En la máquina donde
        apareció el problema llegó a 168 MB y 1,6 millones de filas, con el
        dashboard inutilizable. Un tope de filas resuelve eso sin pedirle
        mantenimiento a nadie: se conservan las más recientes, que son las
        únicas que el panel muestra.

        El chequeo no va en cada INSERT (sería un COUNT por conexión): se
        hace cada `PRUNE_EVERY` inserciones, que es suficientemente seguido
        para que el archivo no se dispare y suficientemente espaciado para
        no costar nada.
        """
        if self.max_rows <= 0:
            return
        self._inserts_since_prune += 1
        if self._inserts_since_prune < self.PRUNE_EVERY:
            return
        self._inserts_since_prune = 0
        self.prune()

    def prune(self) -> int:
        """Borra las filas más viejas que exceden `max_rows`. Devuelve
        cuántas borró."""
        if self.max_rows <= 0:
            return 0
        with self._lock, closing(self._connect()) as conn, conn:
            total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            sobrante = total - self.max_rows
            if sobrante <= 0:
                return 0
            # Se borra por id (autoincremental): las de id más chico son las
            # más viejas, sin depender de parsear fechas.
            conn.execute(
                "DELETE FROM requests WHERE id IN ("
                "  SELECT id FROM requests ORDER BY id ASC LIMIT ?"
                ")",
                (sobrante,),
            )
            conn.commit()
            return sobrante

    def compact(self) -> None:
        """Devuelve al disco el espacio de las filas borradas (VACUUM).

        Importa: sin esto, SQLite marca las páginas como libres para
        reusarlas pero el archivo sigue ocupando los mismos megabytes.
        """
        # VACUUM no puede correr dentro de una transacción, así que se abre
        # la conexión a mano en vez de usar el context manager.
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("VACUUM")
            finally:
                conn.close()

    def clear(self) -> int:
        """Vacía el historial entero y compacta. Devuelve cuántas borró."""
        with self._lock, closing(self._connect()) as conn, conn:
            borradas = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            conn.execute("DELETE FROM requests")
            conn.commit()
        self.compact()
        return borradas

    def recent_blocked(self, limit: int = 20) -> list[tuple]:
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                """
                SELECT timestamp, host, reason FROM requests
                WHERE blocked = 1
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return cur.fetchall()

    def stats(self, ocultar: bool = False) -> dict:
        """Totales del panel. `ocultar` saca de la cuenta los dominios
        ruidosos, y además informa cuántas conexiones se sacaron: el panel
        muestra ese número para que nunca haya un total que no cierra sin
        explicación."""
        filtro, params = self._filtro_ocultos(ocultar)
        donde = f"WHERE {filtro}" if filtro else ""
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM requests {donde}", params
            ).fetchone()[0]
            blocked = conn.execute(
                "SELECT COUNT(*) FROM requests "
                f"WHERE (blocked = 1 OR reason LIKE '[AUDIT]%'){y_ademas}", params
            ).fetchone()[0]
            if filtro:
                total_real = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            else:
                total_real = total
        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "ocultas": total_real - total,
        }

    # ---------- consultas para el dashboard ----------

    @staticmethod
    def _filtro_ocultos(ocultar: bool) -> tuple[str, list]:
        """Fragmento SQL que deja afuera las conexiones marcadas como ruido.

        El filtro se apoya en la columna `noisy`, que se escribe al insertar
        (y se recalcula con `remarcar_ruido` cuando cambia la lista). La
        alternativa -comparar el host contra los ~50 dominios de la lista en
        cada consulta- se probó y no sirve: son 100 comparaciones con LIKE
        por fila, la tabla entera en cada refresco, y con 200.000 filas el
        panel pasaba de milisegundos a 3 segundos.

        Tiene que hacerse en SQL y no filtrando después en Python porque las
        agregaciones usan GROUP BY con LIMIT: filtrando después, los dominios
        ruidosos igual se comerían los primeros puestos del Top 10 y quedaría
        una lista de tres elementos.
        """
        if not ocultar:
            return "", []
        return "noisy = 0", []

    def remarcar_ruido(self, es_ruidoso) -> int:
        """Recalcula la marca de ruido de TODO el historial. Devuelve cuántas
        filas cambiaron.

        Se corre al arrancar el proxy, para que una base que ya existía (o
        una lista de dominios que se editó a mano) quede consistente. Es
        barato aunque la tabla sea grande: la cantidad de hosts DISTINTOS es
        de unos cientos, así que el matcheo se hace en Python sobre esa lista
        chica y el UPDATE va por igualdad de host, apoyado en su índice.
        """
        with self._lock, closing(self._connect()) as conn, conn:
            hosts = [h for (h,) in conn.execute("SELECT DISTINCT host FROM requests")]
            ruidosos = [h for h in hosts if h and es_ruidoso(h)]
            cambios = 0
            if ruidosos:
                marcas = ",".join("?" * len(ruidosos))
                cur = conn.execute(
                    f"UPDATE requests SET noisy = 1 WHERE noisy = 0 AND host IN ({marcas})",
                    ruidosos,
                )
                cambios += cur.rowcount
                cur = conn.execute(
                    f"UPDATE requests SET noisy = 0 WHERE noisy = 1 AND host NOT IN ({marcas})",
                    ruidosos,
                )
                cambios += cur.rowcount
            else:
                cur = conn.execute("UPDATE requests SET noisy = 0 WHERE noisy = 1")
                cambios += cur.rowcount
            conn.commit()
            return cambios

    COLUMNAS = (
        "id", "timestamp", "client_ip", "method", "host", "port",
        "path", "blocked", "reason", "duration_ms",
        "dest_ip", "country", "asn", "provider",
        "process", "bytes_out", "bytes_in",
    )

    def _filas(self, cur) -> list[dict]:
        return [dict(zip(self.COLUMNAS, fila)) for fila in cur.fetchall()]

    def buscar(
        self,
        texto: str = "",
        solo_bloqueadas: bool = True,
        limit: int = 25,
        ocultar: bool = False,
    ) -> list[dict]:
        """Historial filtrado, con TODAS las columnas de cada conexión.

        `texto` busca por host o por IP del cliente, con coincidencia parcial:
        escribir "google" trae también "www.google.com". Cuando hay búsqueda,
        el filtro de "solo bloqueadas" se ignora a propósito -si estás
        auditando una IP querés ver todo lo que hizo, no solo lo que se le
        bloqueó-. Y por la misma razón se ignora el filtro de ruido: si
        buscás un dominio de telemetría, es porque lo querés ver.
        """
        condiciones = []
        parametros: list = []
        texto = (texto or "").strip()
        if not texto:
            filtro, params_ocultos = self._filtro_ocultos(ocultar)
            if filtro:
                condiciones.append(filtro)
                parametros += params_ocultos
        if texto:
            # Se busca también por IP de destino, país y proveedor: auditar
            # "qué mandé a Rusia" o "qué toca esta IP" es justo para lo que
            # sirven esas columnas.
            condiciones.append(
                "(host LIKE ? OR client_ip LIKE ? OR dest_ip LIKE ? "
                " OR country LIKE ? OR provider LIKE ? OR process LIKE ?)"
            )
            parametros += [f"%{texto}%"] * 6
        elif solo_bloqueadas:
            # También entran las de modo audit. En audit la conexión se deja
            # pasar (blocked=0) pero se registra el motivo por el que se
            # hubiera cortado, y ese es TODO el punto del modo: ver qué
            # pasaría. Filtrando solo por blocked=1, el panel mostraba
            # "todavía no se bloqueó nada" mientras la base acumulaba todo
            # invisible, y el nivel Paranoico -que fuerza audit- quedaba
            # inservible.
            condiciones.append("(blocked = 1 OR reason LIKE '[AUDIT]%')")
        where = f"WHERE {' AND '.join(condiciones)}" if condiciones else ""

        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                f"SELECT {', '.join(self.COLUMNAS)} FROM requests {where} "
                "ORDER BY id DESC LIMIT ?",
                (*parametros, limit),
            )
            return self._filas(cur)

    def por_hora(self, horas: int = 24, ocultar: bool = False) -> list[tuple[str, int, int]]:
        """(hora, total, bloqueadas) de las últimas N horas, para el gráfico.

        Se agrupa por los primeros 13 caracteres del timestamp ISO
        ("2026-07-27T21"), que es exactamente la hora: más barato que parsear
        fechas y funciona con el formato que ya guardamos.

        La ventana se corta por TIEMPO, no por cantidad de franjas. Antes se
        pedían "las últimas 24 franjas que existan", que no es lo mismo: si
        la PC estuvo apagada dos días, esas 24 franjas venían de días
        distintos, y como el gráfico muestra solo la hora, se veían horas
        repetidas y desordenadas (dos "14:00", un "22:00" antes de un
        "19:00"). Con el corte por tiempo, cada hora aparece una sola vez.

        Sale ordenado de la más vieja a la más nueva, que es como se lee un
        gráfico de tiempo.
        """
        from datetime import timedelta

        desde = (datetime.now(timezone.utc) - timedelta(hours=horas)).isoformat()
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT substr(timestamp, 1, 13) AS hora, COUNT(*), "
                "       SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) "
                f"FROM requests WHERE timestamp >= ?{y_ademas} "
                "GROUP BY hora ORDER BY hora ASC",
                (desde, *params),
            )
            return [(h, total, bloq or 0) for h, total, bloq in cur.fetchall()]

    def top_hosts(
        self,
        limit: int = 10,
        solo_bloqueadas: bool = False,
        ocultar: bool = False,
    ) -> list[tuple[str, int]]:
        condiciones = []
        params: list = []
        if solo_bloqueadas:
            condiciones.append("blocked = 1")
        filtro, params_ocultos = self._filtro_ocultos(ocultar)
        if filtro:
            condiciones.append(filtro)
            params += params_ocultos
        where = f"WHERE {' AND '.join(condiciones)}" if condiciones else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                f"SELECT host, COUNT(*) c FROM requests {where} "
                "GROUP BY host ORDER BY c DESC LIMIT ?",
                (*params, limit),
            )
            return cur.fetchall()

    def top_paises(self, limit: int = 10, ocultar: bool = False) -> list[tuple[str, int]]:
        """Adónde va tu tráfico, por país. Solo cuenta lo que tiene país
        resuelto: si no está la base descargada, la lista sale vacía en vez
        de inventar un 'desconocido' gigante."""
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT country, COUNT(*) c FROM requests "
                f"WHERE country IS NOT NULL AND country != ''{y_ademas} "
                "GROUP BY country ORDER BY c DESC LIMIT ?",
                (*params, limit),
            )
            return cur.fetchall()

    def conexiones_sostenidas(
        self, minimo: int = 30, horas: int = 6, ocultar: bool = False
    ) -> list[tuple]:
        """Destinos con MUCHAS conexiones repetidas en las últimas horas.

        Es la señal de un minero: un navegador abre y cierra conexiones a
        muchos destinos distintos, pero un minero martilla el mismo pool sin
        parar durante horas. Detectar eso no requiere mirar el contenido de
        la conexión, que va cifrado: alcanza con la forma del tráfico.

        Devuelve (host, conexiones, primera, última) ordenado por cantidad.
        """
        from datetime import timedelta

        desde = (datetime.now(timezone.utc) - timedelta(hours=horas)).isoformat()
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT host, COUNT(*) c, MIN(timestamp), MAX(timestamp) "
                f"FROM requests WHERE timestamp >= ? AND blocked = 0{y_ademas} "
                "GROUP BY host HAVING c >= ? ORDER BY c DESC LIMIT 20",
                (desde, *params, minimo),
            )
            return cur.fetchall()

    def top_por_volumen(
        self, limit: int = 10, horas: int = 24, ocultar: bool = False
    ) -> list[tuple]:
        """Destinos ordenados por cuánto se les SUBIÓ.

        Lo subido y no lo bajado: bajar mucho es mirar un video, subir mucho
        a un destino que no reconocés es la señal de exfiltración que se
        puede ver sin descifrar nada.
        """
        from datetime import timedelta

        desde = (datetime.now(timezone.utc) - timedelta(hours=horas)).isoformat()
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT host, SUM(bytes_out) s, SUM(bytes_in), "
                "       COALESCE(MAX(process), '') "
                f"FROM requests WHERE timestamp >= ?{y_ademas} "
                "GROUP BY host HAVING s > 0 ORDER BY s DESC LIMIT ?",
                (desde, *params, limit),
            )
            return cur.fetchall()

    def beaconing(self, horas: float = 24, minimo: int = 0,
                  ocultar: bool = False) -> list[dict]:
        """Destinos a los que se sale con intervalos casi exactos.

        ACÁ NO SE CALCULA NADA. La cuenta vive en `beaconing.py` y este método
        solo trae las filas y se la pasa. Antes estaban las dos cosas juntas:
        noventa líneas de SQL más estadística a mano adentro de la clase que
        administra la base.

        Eso era el problema del punto 8 en chiquito. Dos lugares que miden el
        mismo ritmo con umbrales distintos (uno cortaba el jitter en 0.20, el
        otro en 0.25) es un panel que puede mostrar una fila que un test dice
        que no existe. Ahora hay un solo umbral y está escrito una sola vez.

        Devuelve lo que devuelve `beaconing.analizar`: un diccionario por
        grupo, con `proceso`, `destino`, `conexiones`, `promedio`,
        `coeficiente`, `bytes` y `motivo`.
        """
        from . import beaconing as calculo

        filas = self.filas_para_beaconing(horas=horas, ocultar=ocultar)
        return calculo.analizar(filas, minimo=minimo or calculo.MINIMO_DE_CONEXIONES)

    def bloqueos_por_motivo(
        self, limit: int = 10, ocultar: bool = False
    ) -> list[tuple[str, int]]:
        filtro, params = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "SELECT COALESCE(NULLIF(reason, ''), 'sin motivo') AS motivo, COUNT(*) c "
                "FROM requests WHERE (blocked = 1 OR reason LIKE '[AUDIT]%')"
                f"{y_ademas} "
                "GROUP BY motivo ORDER BY c DESC LIMIT ?",
                (*params, limit),
            )
            return cur.fetchall()

    def filas_para_beaconing(self, horas: float = 24, limite: int = 20000,
                             ocultar: bool = False) -> list:
        """El historial crudo que necesita `beaconing.py`: cuándo, a dónde, quién.

        Se traen las conexiones PERMITIDAS y no las bloqueadas, y esa es la
        parte que importa. Un destino bloqueado ya lo agarró una lista: no hace
        falta ningún análisis para saber que estaba mal. Lo que este proxy
        puede contestar y nadie más es qué pasa con lo que **pasó el filtro**:
        un servidor que ninguna lista conoce, con el que un proceso habla cada
        sesenta segundos.

        El tope alto es a propósito: el análisis necesita muchas marcas de
        tiempo para que el ritmo signifique algo, y son filas chicas.
        """
        from datetime import timedelta

        desde = (datetime.now(timezone.utc) - timedelta(hours=horas)).isoformat()
        filtro, params_ocultos = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        with self._lock, closing(self._connect()) as conn:
            filas = conn.execute(
                "SELECT timestamp, host, process, bytes_out, bytes_in "
                f"FROM requests WHERE blocked = 0 AND timestamp >= ?{y_ademas} "
                "ORDER BY id DESC LIMIT ?",
                (desde, *params_ocultos, limite)).fetchall()
        salida = []
        for f in filas:
            # El timestamp está en ISO y el análisis necesita segundos. Se
            # convierte acá y no allá: `beaconing.py` no tiene por qué saber
            # cómo guarda las fechas esta base.
            try:
                ts = datetime.fromisoformat(f[0]).timestamp()
            except (TypeError, ValueError):
                continue
            salida.append({"ts": ts, "host": f[1] or "", "proceso": f[2] or "",
                           "bytes_out": f[3] or 0, "bytes_in": f[4] or 0})
        return salida

    def guardar_ritmos(self, ritmos: list) -> int:
        """Deja en la base los ritmos detectados, y borra los que ya no están.

        El borrado es la parte importante. Sin él, un destino que dejó de
        tener ritmo hace tres semanas seguiría en la tabla y Detect seguiría
        armando incidentes con él: la conclusión quedaría congelada mientras
        el mundo cambió. Se reemplaza la foto entera, que es lo que es.
        """
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM ritmos")
            conn.executemany(
                "INSERT INTO ritmos (proceso, destino, visto, conexiones, "
                "promedio, coeficiente, bytes, motivo) VALUES (?,?,?,?,?,?,?,?)",
                [(r.get("proceso", ""), r["destino"],
                  datetime.now(timezone.utc).isoformat(),
                  int(r.get("conexiones", 0)), float(r.get("promedio", 0.0)),
                  float(r.get("coeficiente", 0.0)), int(r.get("bytes", 0)),
                  r.get("motivo", "")) for r in ritmos])
            conn.commit()
        return len(ritmos)

    def actualizar_ritmos(self, horas: float = 24) -> int:
        """Calcular y guardar. Es lo que corre el bucle de fondo."""
        return self.guardar_ritmos(self.beaconing(horas=horas, ocultar=True))

    def ritmos(self) -> list[dict]:
        with self._lock, closing(self._connect()) as conn:
            conn.row_factory = sqlite3.Row
            filas = conn.execute(
                "SELECT * FROM ritmos ORDER BY coeficiente ASC").fetchall()
        return [dict(f) for f in filas]
