#!/usr/bin/env python3
"""Instala SecureProxy como servicio de systemd, completando todo solo.

Por qué existe: el archivo `.service` tiene tres cosas que dependen de tu
máquina (dónde está el proyecto, con qué usuario corre, dónde está el
python del venv). Editarlas a mano es fácil de hacer mal, y cuando queda mal
systemd falla con un mensaje que no dice gran cosa. Este script las averigua
y las escribe.

    sudo python3 deploy/instalar_servicio.py

Es idempotente: se puede correr de nuevo después de mover el proyecto o de
rehacer el venv, y deja todo apuntando al lugar nuevo.

Para desinstalar:

    sudo python3 deploy/instalar_servicio.py --desinstalar
"""

import argparse
import grp
import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

PROYECTO = Path(__file__).resolve().parent.parent
PLANTILLA = Path(__file__).resolve().parent / "secureproxy.service"
DESTINO = Path("/etc/systemd/system/secureproxy.service")
SERVICIO = "secureproxy"
USUARIO_POR_DEFECTO = "secureproxy"


def salir(mensaje: str, codigo: int = 1) -> int:
    print(f"ERROR: {mensaje}")
    return codigo


def es_linux_con_systemd() -> bool:
    return sys.platform.startswith("linux") and Path("/run/systemd/system").exists()


def buscar_python() -> Path | None:
    """El intérprete que va a usar el servicio.

    Se prefiere el venv del proyecto, que es donde están las dependencias.
    Si no hay venv, se cae al python del sistema, pero avisando: sin las
    dependencias instaladas el servicio va a arrancar y morir enseguida.
    """
    for candidato in (PROYECTO / "venv" / "bin" / "python",
                      PROYECTO / ".venv" / "bin" / "python"):
        if candidato.is_file():
            return candidato
    return None


def asegurar_usuario(nombre: str) -> bool:
    """Crea el usuario de servicio si no existe. Sin shell y sin home: no es
    una cuenta para entrar, es una identidad para correr un proceso."""
    try:
        pwd.getpwnam(nombre)
        return True
    except KeyError:
        pass

    print(f"[instalar] el usuario '{nombre}' no existe, lo creo")
    useradd = shutil.which("useradd")
    if useradd is None:
        print(f"[instalar] no encontré useradd; creá el usuario a mano: useradd -r -s /usr/sbin/nologin {nombre}")
        return False
    resultado = subprocess.run(
        [useradd, "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", nombre],
        capture_output=True, text=True,
    )
    if resultado.returncode != 0:
        print(f"[instalar] no pude crear el usuario: {resultado.stderr.strip()}")
        return False
    return True


def dar_permisos(usuario: str) -> None:
    """El servicio necesita poder escribir data/ y config/.

    Se le da al usuario del servicio la propiedad de esas dos carpetas y
    nada más. El resto del proyecto (el código) queda como está: solo lo
    tiene que leer, y que no pueda modificar su propio código es
    exactamente lo que querés.
    """
    try:
        uid = pwd.getpwnam(usuario).pw_uid
        gid = grp.getgrnam(usuario).gr_gid
    except KeyError:
        try:
            uid = pwd.getpwnam(usuario).pw_uid
            gid = pwd.getpwnam(usuario).pw_gid
        except KeyError:
            print(f"[instalar] no encontré el usuario {usuario}, salteo los permisos")
            return

    for carpeta in ("data", "config"):
        ruta = PROYECTO / carpeta
        ruta.mkdir(parents=True, exist_ok=True)
        os.chown(ruta, uid, gid)
        for hijo in ruta.rglob("*"):
            try:
                os.chown(hijo, uid, gid)
            except OSError:
                pass
        print(f"[instalar] {ruta} ahora es de {usuario}")

    # El .env tiene la API key: que lo lea el servicio y nadie más.
    env = PROYECTO / ".env"
    if env.is_file():
        os.chown(env, uid, gid)
        os.chmod(env, 0o600)
        print(f"[instalar] {env} restringido a {usuario} (600)")


def escribir_unidad(usuario: str, python: Path) -> None:
    texto = PLANTILLA.read_text(encoding="utf-8")
    reemplazos = {
        "User=secureproxy": f"User={usuario}",
        "Group=secureproxy": f"Group={usuario}",
        "WorkingDirectory=/opt/secure-proxy": f"WorkingDirectory={PROYECTO}",
        "ExecStart=/opt/secure-proxy/venv/bin/python -u scripts/run_proxy.py":
            f"ExecStart={python} -u scripts/run_proxy.py",
        "ReadWritePaths=/opt/secure-proxy/data /opt/secure-proxy/config":
            f"ReadWritePaths={PROYECTO / 'data'} {PROYECTO / 'config'}",
    }
    for viejo, nuevo in reemplazos.items():
        if viejo not in texto:
            raise SystemExit(
                f"la plantilla no tiene la línea esperada '{viejo}'. "
                "¿La editaste a mano? Volvé a la del repositorio."
            )
        texto = texto.replace(viejo, nuevo, 1)

    # Si el proyecto está dentro de un home, ProtectHome rompería el acceso.
    # No se activa en la plantilla justamente por esto, pero lo dejamos dicho
    # por si alguien lo agrega después sin darse cuenta.
    if str(PROYECTO).startswith("/home/"):
        # Se ancla en "[Service]\nType=simple" y no en "[Service]" a secas:
        # la palabra aparece antes dentro de un comentario de la sección
        # [Unit], y anclando ahí la línea terminaba en la sección equivocada
        # y de paso partía el comentario al medio.
        ancla = "[Service]\nType=simple"
        if ancla not in texto:
            raise SystemExit("no encuentro el comienzo de la sección [Service] en la plantilla")
        texto = texto.replace(
            ancla,
            ancla + "\n\n# El proyecto vive dentro de /home, así que NO se puede usar\n"
            "# ProtectHome=yes: el servicio no podría ni leer su propio código.\n"
            "ProtectHome=no",
            1,
        )

    DESTINO.write_text(texto, encoding="utf-8")
    DESTINO.chmod(0o644)
    print(f"[instalar] escrito {DESTINO}")


def systemctl(*args: str) -> int:
    return subprocess.run(["systemctl", *args]).returncode


def instalar(usuario: str) -> int:
    python = buscar_python()
    if python is None:
        print("[instalar] AVISO: no encontré el venv del proyecto.")
        print("           Crealo primero, o el servicio va a arrancar y morir:")
        print(f"             cd {PROYECTO}")
        print("             python3 -m venv venv")
        print("             venv/bin/pip install -r requirements.txt")
        return 1
    print(f"[instalar] proyecto : {PROYECTO}")
    print(f"[instalar] python   : {python}")
    print(f"[instalar] usuario  : {usuario}")

    if not asegurar_usuario(usuario):
        return 1
    dar_permisos(usuario)
    escribir_unidad(usuario, python)

    systemctl("daemon-reload")
    if systemctl("enable", "--now", SERVICIO) != 0:
        print("[instalar] el servicio no arrancó. Mirá qué pasó con:")
        print(f"             journalctl -u {SERVICIO} -n 40 --no-pager")
        return 1

    print()
    print("[instalar] listo. El proxy arranca solo con la máquina.")
    print()
    print("  systemctl status secureproxy       ver si está corriendo")
    print("  journalctl -u secureproxy -f       los logs, en vivo")
    print("  sudo systemctl restart secureproxy reiniciarlo")
    print("  sudo systemctl stop secureproxy    pararlo de verdad")
    print()
    print("  El panel sigue en http://127.0.0.1:8889/ del servidor. Como no")
    print("  escucha en la red a propósito, para verlo desde otra máquina:")
    print("      ssh -L 8889:127.0.0.1:8889 usuario@servidor")
    print("  y después abrí http://127.0.0.1:8889/ en tu navegador.")
    return 0


def desinstalar() -> int:
    systemctl("disable", "--now", SERVICIO)
    if DESTINO.exists():
        DESTINO.unlink()
        print(f"[instalar] borrado {DESTINO}")
    systemctl("daemon-reload")
    print("[instalar] servicio desinstalado. El usuario y los datos quedaron.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--usuario", default=USUARIO_POR_DEFECTO,
                        help=f"usuario con el que corre el servicio (default: {USUARIO_POR_DEFECTO})")
    parser.add_argument("--desinstalar", action="store_true")
    args = parser.parse_args()

    if not es_linux_con_systemd():
        return salir(
            "esto es solo para Linux con systemd.\n"
            "       En Windows no hace falta: usá SecureProxy.bat, que ya deja\n"
            "       el proxy arrancando solo con una Tarea Programada."
        )
    if os.geteuid() != 0:
        return salir("hay que correrlo con sudo (escribe en /etc/systemd/system).")
    if not PLANTILLA.is_file():
        return salir(f"no encuentro la plantilla en {PLANTILLA}")

    return desinstalar() if args.desinstalar else instalar(args.usuario)


if __name__ == "__main__":
    sys.exit(main())
