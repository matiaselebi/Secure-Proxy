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

    def beaconing(
        self,
        horas: int = 24,
        minimo: int = 8,
        jitter_maximo: float = 0.20,
        intervalo_minimo: float = 5.0,
        intervalo_maximo: float = 7200.0,
        ocultar: bool = False,
        tope_candidatos: int = 60,
    ) -> list[tuple]:
        """Destinos a los que se sale con intervalos casi exactos.

        Esto detecta algo distinto de `conexiones_sostenidas`, y la
        diferencia importa. Aquella mide VOLUMEN, y con eso se agarra un
        minero: martilla el mismo pool miles de veces. Un implante de
        comando-y-control hace lo contrario, justamente para no llamar la
        atención: se conecta poco, a veces una vez por minuto, pero lo hace
        con una regularidad de reloj porque del otro lado hay un programa
        preguntando "¿hay órdenes nuevas?".

        Entonces la señal no es cuánto, es CADA CUÁNTO. Se calculan los
        intervalos entre conexiones consecutivas y se mira su dispersión
        relativa (desvío estándar sobre promedio, o "jitter"): un humano
        navegando da valores altísimos, un programa automático da valores
        cerca de cero.

        Se descartan a propósito:

        - Los intervalos muy cortos (menos de 5 segundos): eso es una página
          cargando sus recursos, no un beacon.
        - Los muy largos (más de 2 horas): con tan pocas muestras, cualquier
          cosa parece regular.
        - Los destinos con demasiadas conexiones: si algo se conectó 5.000
          veces, es volumen y ya lo agarra el otro detector.

        Esto NO bloquea nada: una app de mensajería o un cliente de correo
        que revisa cada 60 segundos da exactamente la misma firma. Es una
        lista de "andá a mirar esto", no de culpables.

        Devuelve (host, conexiones, intervalo_promedio_seg, jitter, proceso).
        """
        from datetime import timedelta

        desde = (datetime.now(timezone.utc) - timedelta(hours=horas)).isoformat()
        filtro, params_ocultos = self._filtro_ocultos(ocultar)
        y_ademas = f" AND {filtro}" if filtro else ""
        # Un beacon no hace miles de conexiones: ese es el otro detector.
        maximo = int(horas * 3600 / intervalo_minimo)

        with self._lock, closing(self._connect()) as conn, conn:
            candidatos = conn.execute(
                "SELECT host, COUNT(*) c FROM requests "
                f"WHERE timestamp >= ?{y_ademas} "
                "GROUP BY host HAVING c >= ? AND c <= ? "
                "ORDER BY c DESC LIMIT ?",
                (desde, *params_ocultos, minimo, maximo, tope_candidatos),
            ).fetchall()

            resultados = []
            for host, cantidad in candidatos:
                filas = conn.execute(
                    "SELECT timestamp, process FROM requests "
                    "WHERE host = ? AND timestamp >= ? ORDER BY timestamp ASC",
                    (host, desde),
                ).fetchall()
                momentos = []
                proceso = ""
                for marca, proc in filas:
                    try:
                        momentos.append(datetime.fromisoformat(str(marca)).timestamp())
                    except (TypeError, ValueError):
                        continue
                    if proc and not proceso:
                        proceso = proc
                if len(momentos) < minimo:
                    continue

                intervalos = [b - a for a, b in zip(momentos, momentos[1:]) if b > a]
                if len(intervalos) < minimo - 1:
                    continue
                promedio = sum(intervalos) / len(intervalos)
                if not (intervalo_minimo <= promedio <= intervalo_maximo):
                    continue
                varianza = sum((x - promedio) ** 2 for x in intervalos) / len(intervalos)
                jitter = (varianza ** 0.5) / promedio
                if jitter <= jitter_maximo:
                    resultados.append((host, cantidad, promedio, jitter, proceso))

        # Lo más regular primero: es lo más sospechoso.
        resultados.sort(key=lambda fila: fila[3])
        return resultados

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
