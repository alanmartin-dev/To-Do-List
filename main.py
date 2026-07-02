#!/usr/bin/env python3
"""
================================================================================
 TO-DO LIST CLI  ·  Aplicación de lista de tareas para consola
================================================================================
Compatible con Python 3.14+ (solo librería estándar, sin dependencias externas).

Características:
    - Autenticación obligatoria antes de acceder a la app (3 intentos máx.).
    - Credenciales leídas desde un archivo .env (usuario + hash PBKDF2-SHA256).
    - Contraseña enmascarada en pantalla al escribirla (getpass).
    - Tareas con 5 campos: ID, Título, Estado, Fecha límite, Prioridad.
    - Persistencia en tareas.json.
    - CRUD completo + cambio de estado (Pendiente / Realizada / Olvidada).
    - Interfaz de consola con colores ANSI, cajas y tablas alineadas.

Autor: Backend Dev (Python) — para Martin
================================================================================
"""

from __future__ import annotations

import os
import sys
import json
import hmac
import hashlib
import getpass
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional


# ==============================================================================
# 1. CONFIGURACIÓN GLOBAL
# ==============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
TASKS_FILE = os.path.join(BASE_DIR, "tareas.json")

MAX_LOGIN_ATTEMPTS = 3
PBKDF2_ITERATIONS = 100_000

ESTADOS_VALIDOS = ("Pendiente", "Realizada", "Olvidada")
PRIORIDADES_VALIDAS = ("Alta", "Media", "Baja")

ANCHO_UI = 64


# ==============================================================================
# 2. ESTILO DE CONSOLA (ANSI)
# ==============================================================================

class Color:
    """Códigos ANSI reutilizables para dar estilo a la terminal."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    BG_BLUE = "\033[44m"


COLOR_ESTADO = {
    "Pendiente": Color.YELLOW,
    "Realizada": Color.GREEN,
    "Olvidada": Color.GRAY,
}

COLOR_PRIORIDAD = {
    "Alta": Color.RED,
    "Media": Color.YELLOW,
    "Baja": Color.CYAN,
}


def limpiar_pantalla() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def linea(char: str = "═", ancho: int = ANCHO_UI, color: str = Color.CYAN) -> str:
    return f"{color}{char * ancho}{Color.RESET}"


def caja(texto: str, color: str = Color.CYAN, ancho: int = ANCHO_UI) -> None:
    """Imprime un bloque de texto centrado dentro de una caja ASCII."""
    lineas_texto = texto.split("\n")
    print(f"{color}╔{'═' * ancho}╗{Color.RESET}")
    for l in lineas_texto:
        print(f"{color}║{Color.RESET}{l.center(ancho)}{color}║{Color.RESET}")
    print(f"{color}╚{'═' * ancho}╝{Color.RESET}")


def encabezado(titulo: str) -> None:
    limpiar_pantalla()
    caja(f"{Color.BOLD}{titulo}{Color.RESET}", color=Color.MAGENTA)
    print()


def pausar() -> None:
    input(f"\n{Color.DIM}Presiona ENTER para continuar...{Color.RESET}")


def alerta_error(mensaje: str) -> None:
    print(f"\n{Color.RED}{Color.BOLD}✗ {mensaje}{Color.RESET}")


def alerta_exito(mensaje: str) -> None:
    print(f"\n{Color.GREEN}{Color.BOLD}✓ {mensaje}{Color.RESET}")


def alerta_info(mensaje: str) -> None:
    print(f"\n{Color.CYAN}ℹ {mensaje}{Color.RESET}")


# ==============================================================================
# 3. CARGA DE VARIABLES DE ENTORNO (.env) — sin dependencias externas
# ==============================================================================

def cargar_env(path: str) -> dict:
    """
    Parser mínimo de archivos .env (formato KEY=VALUE).
    No requiere instalar python-dotenv; solo usa la librería estándar.
    """
    variables: dict[str, str] = {}
    if not os.path.exists(path):
        return variables

    with open(path, "r", encoding="utf-8") as f:
        for linea_raw in f:
            linea_limpia = linea_raw.strip()
            if not linea_limpia or linea_limpia.startswith("#") or "=" not in linea_limpia:
                continue
            clave, _, valor = linea_limpia.partition("=")
            variables[clave.strip()] = valor.strip().strip('"').strip("'")
    return variables


# ==============================================================================
# 4. AUTENTICACIÓN Y SEGURIDAD
# ==============================================================================

class AuthError(Exception):
    """Error de configuración de credenciales."""


class AuthManager:
    """
    Gestiona el login del sistema. Las credenciales reales NUNCA se guardan
    en texto plano: se compara el hash PBKDF2-HMAC-SHA256 de la contraseña
    ingresada contra el hash almacenado en el .env (con salt aleatorio).
    """

    def __init__(self, env_path: str):
        env = cargar_env(env_path)
        self.username = env.get("APP_USERNAME")
        self.password_hash = env.get("APP_PASSWORD_HASH")
        salt_hex = env.get("APP_SALT")

        if not all([self.username, self.password_hash, salt_hex]):
            raise AuthError(
                "No se encontraron credenciales válidas en el archivo .env.\n"
                "   Se requieren: APP_USERNAME, APP_PASSWORD_HASH, APP_SALT.\n"
                "   Ejecuta 'generar_credenciales.py' para crearlas."
            )
        try:
            self.salt = bytes.fromhex(salt_hex)
        except ValueError as exc:
            raise AuthError("APP_SALT en el .env no es un hexadecimal válido.") from exc

    @staticmethod
    def hashear_password(password: str, salt: bytes) -> str:
        """Deriva un hash seguro de la contraseña usando PBKDF2-HMAC-SHA256."""
        derivado = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        return derivado.hex()

    def verificar(self, username: str, password: str) -> bool:
        """Compara credenciales usando comparación segura contra timing attacks."""
        usuario_ok = hmac.compare_digest(username.strip(), self.username)
        hash_calculado = self.hashear_password(password, self.salt)
        password_ok = hmac.compare_digest(hash_calculado, self.password_hash)
        return usuario_ok and password_ok


def realizar_login(auth: AuthManager) -> bool:
    """
    Solicita usuario y contraseña (enmascarada) hasta MAX_LOGIN_ATTEMPTS veces.
    Retorna True si el login fue exitoso, False si se agotaron los intentos.
    """
    encabezado("🔐  ACCESO AL SISTEMA — TO-DO LIST")

    for intento in range(1, MAX_LOGIN_ATTEMPTS + 1):
        restantes = MAX_LOGIN_ATTEMPTS - intento + 1
        print(f"{Color.DIM}Intento {intento}/{MAX_LOGIN_ATTEMPTS}{Color.RESET}")

        usuario = input(f"{Color.BLUE}👤 Usuario:    {Color.RESET}").strip()
        # getpass enmascara la contraseña por completo (no se muestra en pantalla)
        password = getpass.getpass(f"{Color.BLUE}🔑 Contraseña: {Color.RESET}")

        if auth.verificar(usuario, password):
            alerta_exito(f"Bienvenido, {usuario}. Autenticación correcta.")
            return True

        intentos_fallidos_restantes = restantes - 1
        if intentos_fallidos_restantes > 0:
            alerta_error(
                f"Credenciales incorrectas. Te quedan {intentos_fallidos_restantes} intento(s)."
            )
            print()
        else:
            alerta_error("Credenciales incorrectas. Se agotaron los intentos.")

    return False


# ==============================================================================
# 5. MODELO DE DATOS — TAREA (máximo 5 campos)
# ==============================================================================

@dataclass
class Tarea:
    """Modelo de una tarea. Exactamente 5 campos, como exige el requerimiento."""
    id: int
    titulo: str
    estado: str = "Pendiente"
    fecha_limite: str = ""     # formato YYYY-MM-DD
    prioridad: str = "Media"

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "Tarea":
        return Tarea(
            id=int(data["id"]),
            titulo=str(data.get("titulo", "")),
            estado=str(data.get("estado", "Pendiente")),
            fecha_limite=str(data.get("fecha_limite", "")),
            prioridad=str(data.get("prioridad", "Media")),
        )


# ==============================================================================
# 6. CAPA DE PERSISTENCIA Y LÓGICA DE NEGOCIO
# ==============================================================================

class TaskManager:
    """Administra el ciclo de vida de las tareas y su persistencia en JSON."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.tareas: list[Tarea] = []
        self._cargar()

    # ---- persistencia ----------------------------------------------------
    def _cargar(self) -> None:
        if not os.path.exists(self.filepath):
            self.tareas = []
            return
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.tareas = [Tarea.from_dict(t) for t in data]
        except (json.JSONDecodeError, TypeError, KeyError, ValueError):
            # Archivo corrupto o vacío: se arranca con una lista limpia
            self.tareas = []

    def _guardar(self) -> None:
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(
                [t.to_dict() for t in self.tareas], f, ensure_ascii=False, indent=4
            )

    def _siguiente_id(self) -> int:
        return max((t.id for t in self.tareas), default=0) + 1

    # ---- operaciones CRUD ---------------------------------------------------
    def agregar(self, titulo: str, fecha_limite: str, prioridad: str) -> Tarea:
        tarea = Tarea(
            id=self._siguiente_id(),
            titulo=titulo.strip(),
            estado="Pendiente",
            fecha_limite=fecha_limite.strip(),
            prioridad=prioridad,
        )
        self.tareas.append(tarea)
        self._guardar()
        return tarea

    def obtener(self, id_: int) -> Optional[Tarea]:
        return next((t for t in self.tareas if t.id == id_), None)

    def editar(
        self,
        id_: int,
        titulo: Optional[str] = None,
        fecha_limite: Optional[str] = None,
        prioridad: Optional[str] = None,
    ) -> bool:
        """Permite editar las actividades pendientes (título, fecha, prioridad)."""
        tarea = self.obtener(id_)
        if tarea is None:
            return False
        if titulo:
            tarea.titulo = titulo.strip()
        if fecha_limite:
            tarea.fecha_limite = fecha_limite.strip()
        if prioridad:
            tarea.prioridad = prioridad
        self._guardar()
        return True

    def cambiar_estado(self, id_: int, nuevo_estado: str) -> bool:
        if nuevo_estado not in ESTADOS_VALIDOS:
            return False
        tarea = self.obtener(id_)
        if tarea is None:
            return False
        tarea.estado = nuevo_estado
        self._guardar()
        return True

    def eliminar(self, id_: int) -> bool:
        tarea = self.obtener(id_)
        if tarea is None:
            return False
        self.tareas.remove(tarea)
        self._guardar()
        return True

    def listar(self, filtro_estado: Optional[str] = None) -> list[Tarea]:
        if filtro_estado:
            return [t for t in self.tareas if t.estado == filtro_estado]
        return list(self.tareas)


# ==============================================================================
# 7. UTILIDADES DE ENTRADA / VALIDACIÓN
# ==============================================================================

def pedir_texto_no_vacio(prompt: str) -> str:
    while True:
        valor = input(prompt).strip()
        if valor:
            return valor
        alerta_error("Este campo no puede estar vacío.")


def pedir_fecha_opcional(prompt: str) -> str:
    """Valida formato YYYY-MM-DD. Cadena vacía = sin fecha límite."""
    while True:
        valor = input(prompt).strip()
        if not valor:
            return ""
        try:
            datetime.strptime(valor, "%Y-%m-%d")
            return valor
        except ValueError:
            alerta_error("Formato de fecha inválido. Usa YYYY-MM-DD (ej. 2026-07-15).")


def pedir_opcion(prompt: str, opciones: tuple[str, ...]) -> str:
    etiquetas = " / ".join(f"{i+1}={op}" for i, op in enumerate(opciones))
    while True:
        valor = input(f"{prompt} ({etiquetas}): ").strip()
        if valor in opciones:
            return valor
        if valor.isdigit() and 1 <= int(valor) <= len(opciones):
            return opciones[int(valor) - 1]
        alerta_error("Opción inválida.")


def pedir_id(prompt: str) -> Optional[int]:
    valor = input(prompt).strip()
    if not valor.isdigit():
        alerta_error("El ID debe ser un número entero.")
        return None
    return int(valor)


# ==============================================================================
# 8. INTERFAZ DE CONSOLA — TABLA DE TAREAS
# ==============================================================================

COL_ID, COL_TITULO, COL_ESTADO, COL_FECHA, COL_PRIORIDAD = 4, 28, 12, 12, 10


def _fmt_fila(id_, titulo, estado, fecha, prioridad, es_header=False) -> str:
    titulo = (titulo[: COL_TITULO - 3] + "...") if len(titulo) > COL_TITULO else titulo
    if es_header:
        return (
            f"{Color.BOLD}{str(id_).ljust(COL_ID)} "
            f"{titulo.ljust(COL_TITULO)} "
            f"{estado.ljust(COL_ESTADO)} "
            f"{fecha.ljust(COL_FECHA)} "
            f"{prioridad.ljust(COL_PRIORIDAD)}{Color.RESET}"
        )

    color_estado = COLOR_ESTADO.get(estado, Color.WHITE)
    color_prioridad = COLOR_PRIORIDAD.get(prioridad, Color.WHITE)
    fecha_mostrar = fecha if fecha else "—"
    return (
        f"{Color.WHITE}{str(id_).ljust(COL_ID)}{Color.RESET} "
        f"{titulo.ljust(COL_TITULO)} "
        f"{color_estado}{estado.ljust(COL_ESTADO)}{Color.RESET} "
        f"{Color.DIM}{fecha_mostrar.ljust(COL_FECHA)}{Color.RESET} "
        f"{color_prioridad}{prioridad.ljust(COL_PRIORIDAD)}{Color.RESET}"
    )


def mostrar_tabla_tareas(tareas: list[Tarea]) -> None:
    if not tareas:
        alerta_info("No hay tareas para mostrar.")
        return

    print(_fmt_fila("ID", "TÍTULO", "ESTADO", "FECHA LÍM.", "PRIORIDAD", es_header=True))
    print(linea("─", color=Color.GRAY))
    for t in tareas:
        print(_fmt_fila(t.id, t.titulo, t.estado, t.fecha_limite, t.prioridad))
    print(linea("─", color=Color.GRAY))
    print(f"{Color.DIM}Total: {len(tareas)} tarea(s){Color.RESET}")


# ==============================================================================
# 9. APLICACIÓN PRINCIPAL (MENÚ)
# ==============================================================================

class App:
    def __init__(self):
        self.tasks = TaskManager(TASKS_FILE)

    # ---- pantallas ------------------------------------------------------
    def mostrar_menu(self) -> None:
        encabezado("📋  TO-DO LIST — MENÚ PRINCIPAL")
        opciones = [
            "1. Ver todas las tareas",
            "2. Ver tareas por estado",
            "3. Agregar nueva tarea",
            "4. Editar tarea",
            "5. Cambiar estado de tarea",
            "6. Eliminar tarea",
            "7. Salir",
        ]
        for op in opciones:
            print(f"  {Color.CYAN}{op}{Color.RESET}")
        print(linea("─", color=Color.GRAY))

    def ejecutar(self) -> None:
        while True:
            self.mostrar_menu()
            opcion = input(f"\n{Color.BOLD}Elige una opción (1-7): {Color.RESET}").strip()

            if opcion == "1":
                self._ver_todas()
            elif opcion == "2":
                self._ver_por_estado()
            elif opcion == "3":
                self._agregar_tarea()
            elif opcion == "4":
                self._editar_tarea()
            elif opcion == "5":
                self._cambiar_estado()
            elif opcion == "6":
                self._eliminar_tarea()
            elif opcion == "7":
                encabezado("👋  HASTA PRONTO")
                print(f"{Color.GREEN}Sesión cerrada. ¡Nos vemos pronto!{Color.RESET}\n")
                break
            else:
                alerta_error("Opción no válida, intenta de nuevo.")
                pausar()

    # ---- acciones del menú ------------------------------------------------
    def _ver_todas(self) -> None:
        encabezado("📄  TODAS LAS TAREAS")
        mostrar_tabla_tareas(self.tasks.listar())
        pausar()

    def _ver_por_estado(self) -> None:
        encabezado("🔎  FILTRAR POR ESTADO")
        estado = pedir_opcion("Estado a filtrar", ESTADOS_VALIDOS)
        print()
        mostrar_tabla_tareas(self.tasks.listar(filtro_estado=estado))
        pausar()

    def _agregar_tarea(self) -> None:
        encabezado("➕  AGREGAR NUEVA TAREA")
        titulo = pedir_texto_no_vacio(f"{Color.BLUE}Título de la tarea: {Color.RESET}")
        fecha = pedir_fecha_opcional(
            f"{Color.BLUE}Fecha límite (YYYY-MM-DD, opcional): {Color.RESET}"
        )
        prioridad = pedir_opcion(f"{Color.BLUE}Prioridad", PRIORIDADES_VALIDAS)
        tarea = self.tasks.agregar(titulo, fecha, prioridad)
        alerta_exito(f"Tarea #{tarea.id} creada correctamente.")
        pausar()

    def _editar_tarea(self) -> None:
        encabezado("✏️  EDITAR TAREA")
        mostrar_tabla_tareas(self.tasks.listar())
        print()
        id_ = pedir_id(f"{Color.BLUE}ID de la tarea a editar: {Color.RESET}")
        if id_ is None:
            pausar()
            return

        tarea = self.tasks.obtener(id_)
        if tarea is None:
            alerta_error(f"No existe una tarea con ID {id_}.")
            pausar()
            return

        alerta_info("Deja el campo vacío para conservar el valor actual.")
        nuevo_titulo = input(
            f"{Color.BLUE}Nuevo título [{tarea.titulo}]: {Color.RESET}"
        ).strip()
        nueva_fecha = pedir_fecha_opcional(
            f"{Color.BLUE}Nueva fecha límite [{tarea.fecha_limite or '—'}] (YYYY-MM-DD): {Color.RESET}"
        )
        nueva_prioridad_in = input(
            f"{Color.BLUE}Nueva prioridad [{tarea.prioridad}] "
            f"({'/'.join(PRIORIDADES_VALIDAS)}, vacío = no cambiar): {Color.RESET}"
        ).strip()
        nueva_prioridad = nueva_prioridad_in if nueva_prioridad_in in PRIORIDADES_VALIDAS else None

        self.tasks.editar(
            id_,
            titulo=nuevo_titulo or None,
            fecha_limite=nueva_fecha or None,
            prioridad=nueva_prioridad,
        )
        alerta_exito(f"Tarea #{id_} actualizada correctamente.")
        pausar()

    def _cambiar_estado(self) -> None:
        encabezado("🔄  CAMBIAR ESTADO DE TAREA")
        mostrar_tabla_tareas(self.tasks.listar())
        print()
        id_ = pedir_id(f"{Color.BLUE}ID de la tarea: {Color.RESET}")
        if id_ is None:
            pausar()
            return
        if self.tasks.obtener(id_) is None:
            alerta_error(f"No existe una tarea con ID {id_}.")
            pausar()
            return

        nuevo_estado = pedir_opcion("Nuevo estado", ESTADOS_VALIDOS)
        self.tasks.cambiar_estado(id_, nuevo_estado)
        alerta_exito(f"Tarea #{id_} ahora está en estado: {nuevo_estado}.")
        pausar()

    def _eliminar_tarea(self) -> None:
        encabezado("🗑️  ELIMINAR TAREA")
        mostrar_tabla_tareas(self.tasks.listar())
        print()
        id_ = pedir_id(f"{Color.BLUE}ID de la tarea a eliminar: {Color.RESET}")
        if id_ is None:
            pausar()
            return

        confirmacion = input(
            f"{Color.RED}¿Confirmas eliminar la tarea #{id_}? (s/n): {Color.RESET}"
        ).strip().lower()
        if confirmacion == "s":
            if self.tasks.eliminar(id_):
                alerta_exito(f"Tarea #{id_} eliminada.")
            else:
                alerta_error(f"No existe una tarea con ID {id_}.")
        else:
            alerta_info("Operación cancelada.")
        pausar()


# ==============================================================================
# 10. PUNTO DE ENTRADA
# ==============================================================================

def main() -> None:
    try:
        auth = AuthManager(ENV_PATH)
    except AuthError as exc:
        alerta_error(str(exc))
        sys.exit(1)

    try:
        if not realizar_login(auth):
            alerta_error("Número máximo de intentos alcanzado. Cerrando programa.")
            sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n{Color.YELLOW}Login cancelado por el usuario.{Color.RESET}")
        sys.exit(1)

    pausar()
    try:
        App().ejecutar()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n{Color.YELLOW}Programa interrumpido. ¡Hasta luego!{Color.RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
