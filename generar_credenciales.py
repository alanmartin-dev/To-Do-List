#!/usr/bin/env python3
"""
Utilidad de línea de comandos para (re)generar las credenciales del .env.

Genera un salt aleatorio y un hash PBKDF2-HMAC-SHA256 de la contraseña
ingresada (enmascarada), y los escribe en el archivo .env junto al usuario.

Uso:
    python generar_credenciales.py
"""

import os
import getpass
import hashlib
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
PBKDF2_ITERATIONS = 100_000


def main() -> None:
    print("=== Generador de credenciales — To-Do List CLI ===\n")

    usuario = input("Nuevo nombre de usuario: ").strip()
    while not usuario:
        usuario = input("El usuario no puede estar vacío. Nuevo nombre de usuario: ").strip()

    while True:
        password = getpass.getpass("Nueva contraseña: ")
        confirmar = getpass.getpass("Confirma la contraseña: ")
        if password != confirmar:
            print("✗ Las contraseñas no coinciden. Intenta de nuevo.\n")
            continue
        if len(password) < 6:
            print("✗ La contraseña debe tener al menos 6 caracteres.\n")
            continue
        break

    salt = secrets.token_bytes(16)
    hash_derivado = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    ).hex()

    contenido = (
        "# Credenciales de acceso \n"
        f"APP_USERNAME={usuario}\n"
        f"APP_PASSWORD_HASH={hash_derivado}\n"
        f"APP_SALT={salt.hex()}\n"
    )

    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.write(contenido)

    print(f"\n✓ Credenciales guardadas")

if __name__ == "__main__":
    main()
