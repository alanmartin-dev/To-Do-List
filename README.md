# 📋 To-Do List CLI (Python 3.14)

Aplicación de lista de tareas para consola, con autenticación obligatoria y
persistencia en JSON.
## Archivos

| Archivo                   | Descripción                                                        |
|----------------------------|--------------------------------------------------------------------|
| `main.py`                 | Aplicación principal (login + menú de tareas).                     |
| `generar_credenciales.py` | Utilidad para crear/cambiar el usuario y contraseña del `.env`.    |
| `tareas.json`              | Se crea automáticamente al agregar la primera tarea.               |

Para crear tus propias credenciales:

```bash
python3 generar_credenciales.py
```

## Ejecución

```bash
python3 main.py
```

1. Ingresa usuario y contraseña (la contraseña se escribe **enmascarada**,
   no se muestra en pantalla). Tienes **3 intentos**; si fallas los 3, el
   programa se cierra automáticamente.
2. Una vez dentro, usa el menú numérico para:
   - Ver todas las tareas / filtrar por estado
   - Agregar una tarea
   - Editar una tarea (título, fecha límite, prioridad)
   - Cambiar el estado: `Pendiente`, `Realizada` u `Olvidada`
   - Eliminar una tarea

## Modelo de datos (`tareas.json`)

Cada tarea tiene exactamente 5 campos:

```json
{
    "id": 1,
    "titulo": "Terminar informe de estadística",
    "estado": "Pendiente",
    "fecha_limite": "2026-07-10",
    "prioridad": "Alta"
}
```

- `estado` ∈ `{"Pendiente", "Realizada", "Olvidada"}`
- `prioridad` ∈ `{"Alta", "Media", "Baja"}`
- `fecha_limite` en formato `YYYY-MM-DD` (opcional)

## Notas de diseño
- **Colores ANSI**: si tu terminal no soporta ANSI (algunas consolas antiguas
  de Windows), instala Windows Terminal o usa PowerShell moderno.
- Código organizado en secciones: estilo de consola, auth, modelo de datos,
  persistencia, validación de entradas y UI del menú — cada una con su propia
  responsabilidad para facilitar mantenimiento y pruebas.
