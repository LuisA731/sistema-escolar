# Sistema Escolar Seguro (`sistema-escolar`)

[![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16--alpine-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![pgcrypto](https://img.shields.io/badge/Security-pgcrypto%20%7C%20RBAC-0d9488)](#2-arquitectura-de-seguridad-pgcrypto)

Proyecto práctico de **Seguridad en Bases de Datos y DevOps** implementado con **PostgreSQL 16**, **Docker** y la extensión **`pgcrypto`**. Protege datos personales sensibles (PII) mediante cifrado simétrico AES-256 por columna, hashing adaptativo `bcrypt` para contraseñas y control de acceso basado en roles (**RBAC**) bajo el principio de mínimo privilegio.

---

## 1. Estructura del repositorio

```text
sistema-escolar/
├── Dockerfile                # Imagen PostgreSQL 16 Alpine con scripts SQL embebidos
├── docker-compose.yml        # Orquestación automática, volumen y healthcheck
├── .dockerignore             # Exclusiones del contexto de construcción Docker
├── .env.example              # Plantilla de variables de entorno
├── .gitignore                # Excluye .env, evidencias/ y documentacion/ (uso local)
├── README.md                 # Documentación técnica del repositorio
├── requerimientos.txt        # Especificación funcional y de seguridad
└── sql/
    ├── 01_esquema.sql        # Extensión pgcrypto, tablas, índices, vistas y función auth
    ├── 02_datos.sql          # Datos de prueba cifrados (AES-256) y hashes bcrypt
    └── 03_seguridad.sql      # Roles RBAC, revocación de PUBLIC y permisos granulares
```

> **Nota:** Las carpetas locales `evidencias/` y `documentacion/` están excluidas en `.gitignore` para no subir capturas ni reportes locales al repositorio remoto de GitHub.

---

## 2. Arquitectura de seguridad (`pgcrypto`)

### 2.1 Modelo de datos y columnas protegidas
El esquema (`sistema_escolar`) consta de cinco tablas normalizadas, índices en llaves foráneas, tres vistas de solo lectura sin datos sensibles (`vw_alumnos_basico`, `vw_boleta_consulta`, `vw_resumen_asistencias`) y la función `autenticar_usuario(p_username, p_password)`:

| Tabla | Columnas académicas / operativas | Campos protegidos | Mecanismo |
|---|---|---|---|
| `alumnos` | `id_alumno`, `matricula` (UNIQUE), `nombre_completo`, `fecha_nacimiento`, `fecha_registro` | `curp_cifrado`, `correo_cifrado`, `telefono_cifrado` (`BYTEA`) | `pgp_sym_encrypt` (AES-256) |
| `materias` | `id_materia`, `clave_materia` (UNIQUE), `nombre_materia`, `creditos`, `docente` | — | Catálogo académico |
| `calificaciones` | `id_calificacion`, `id_alumno` (FK), `id_materia` (FK), `periodo`, `calificacion_final` | `observaciones_cifradas` (`BYTEA`) | `pgp_sym_encrypt` (AES-256) |
| `asistencias` | `id_asistencia`, `id_alumno` (FK), `id_materia` (FK), `fecha_clase`, `estado` | `nota_cifrada` (`BYTEA`) | `pgp_sym_encrypt` (AES-256) |
| `usuarios_sistema` | `id_usuario`, `username` (UNIQUE), `rol`, `activo`, `creado_en` | `password_hash` (`TEXT`) | `crypt` + `gen_salt('bf', 10)` |

### 2.2 Cifrado simétrico (`pgp_sym_encrypt` / `pgp_sym_decrypt`)
- **Algoritmo:** OpenPGP simétrico configurado explícitamente con `'cipher-algo=aes256'`.
- **Seguridad semántica:** Cada cifrado genera internamente un *salt* aleatorio y una clave de sesión efímera derivada con S2K, evitando que valores iguales produzcan el mismo bloque binario `BYTEA`.
- **Integridad:** El paquete OpenPGP incluye un código **MDC (Modification Detection Code)** verificado automáticamente por `pgp_sym_decrypt()`, rechazando datos alterados o claves incorrectas.

### 2.3 Hashing de contraseñas (`crypt` + `gen_salt('bf', 10)`)
- **Algoritmo:** `bcrypt` (`'bf'`) con **factor de coste 10** ($2^{10} = 1024$ iteraciones) y *salt* aleatorio de 128 bits incrustado en el hash (`$2a$10$...`).
- **Verificación:** `crypt(input_pass, password_hash) = password_hash`, encapsulado además en `autenticar_usuario()` (`SECURITY DEFINER`, `SET search_path = public, pg_temp`), que valida contraseña y estado `activo` sin exponer `password_hash`.

### 2.4 Gestión, rotación de claves y limitaciones
- **Parametrización en desarrollo:** `docker-compose.yml` toma `APP_ENCRYPTION_KEY` (por defecto `ClaveMaestraEscolar_Dev2026!`) y la pasa al motor como `app.encryption_key`. `sql/02_datos.sql` la lee con `current_setting('app.encryption_key', true)`.
- **Recomendación en producción:** Custodiar la clave en un gestor de secretos externo (Vault, AWS KMS, Azure Key Vault) e inyectarla por transacción con `SET LOCAL app.encryption_key = ...` o cifrar en la capa de aplicación (*envelope encryption*).
- **Rotación de claves:**
  ```sql
  BEGIN;
  UPDATE alumnos
  SET curp_cifrado     = pgp_sym_encrypt(pgp_sym_decrypt(curp_cifrado,     'CLAVE_ANTERIOR'), 'CLAVE_NUEVA', 'cipher-algo=aes256'),
      correo_cifrado   = pgp_sym_encrypt(pgp_sym_decrypt(correo_cifrado,   'CLAVE_ANTERIOR'), 'CLAVE_NUEVA', 'cipher-algo=aes256'),
      telefono_cifrado = pgp_sym_encrypt(pgp_sym_decrypt(telefono_cifrado, 'CLAVE_ANTERIOR'), 'CLAVE_NUEVA', 'cipher-algo=aes256');
  COMMIT;
  ```
- **Limitaciones del cifrado en BD:**
  1. Pasar claves literales en SQL sin parametrizar puede exponerlas en `pg_stat_activity` o logs del servidor.
  2. Las columnas `BYTEA` con *salt* aleatorio no admiten índices B-Tree ni búsquedas `LIKE` directas (requieren *blind index* HMAC-SHA256 adicional para búsquedas exactas indexadas).
  3. El cifrado por columna protege en reposo y respaldos (`pg_dump`), pero debe complementarse con **TLS/SSL** para el tráfico en red.

---

## 3. Despliegue rápido desde cero

### Requisitos previos
- **Docker Engine** y **Docker Compose v2** (o Docker Desktop).

### Clonar e iniciar sin pasos manuales
```bash
git clone <URL_DEL_REPOSITORIO> sistema-escolar
cd sistema-escolar
docker compose up -d --build
```

Al inicializar el volumen vacío por primera vez, PostgreSQL ejecuta automáticamente:
1. `sql/01_esquema.sql`
2. `sql/02_datos.sql`
3. `sql/03_seguridad.sql`

Verificar estado saludable y objetos cargados:
```bash
docker compose ps
docker compose logs postgres-escolar
docker exec -it sistema_escolar_pg psql -U postgres -d sistema_escolar -c "\dx" -c "\dt" -c "\dv" -c "\du"
```

---

## 4. Variables de entorno

Definidas en `docker-compose.yml` y documentadas en `.env.example` (valores de desarrollo/pruebas):

| Variable | Valor por defecto | Descripción |
|---|---|---|
| `POSTGRES_DB` | `sistema_escolar` | Base de datos inicializada automáticamente. |
| `POSTGRES_USER` | `postgres` | Superusuario administrativo del clúster. |
| `POSTGRES_PASSWORD` | `PostgresRootDev2026!` | Contraseña de `postgres` en desarrollo. |
| `POSTGRES_PORT` | `5432` | Puerto expuesto en el equipo anfitrión. |
| `APP_ENCRYPTION_KEY` | `ClaveMaestraEscolar_Dev2026!` | Clave simétrica AES-256 inyectada a `app.encryption_key`. |
| `DOCKER_IMAGE` | `sistema-escolar-db:v1` | Etiqueta de la imagen local o remota. |

---

## 5. Credenciales de prueba y matriz RBAC

`sql/03_seguridad.sql` revoca los privilegios por defecto de `PUBLIC` (incluyendo `ALTER DEFAULT PRIVILEGES`), habilita `scram-sha-256` y aplica mínimo privilegio:

| Usuario | Contraseña | Rol asignado | Permisos efectivos |
|---|---|---|---|
| `postgres` | `PostgresRootDev2026!` | Superusuario | Administración de infraestructura del clúster. |
| `admin` | `Admin123` | `rol_admin` | `ALL PRIVILEGES` sobre `public` + `CREATEROLE`. Descifra PII y gestiona `usuarios_sistema`. |
| `docente_demo` | `Docente123` | `rol_docente` | `SELECT` en vistas, `materias` y columnas no PII de `alumnos`; `SELECT, INSERT, UPDATE` en `calificaciones` y `asistencias`. **Sin acceso** a PII, `DELETE` ni `usuarios_sistema`. |
| `consulta_demo` | `Consulta123` | `rol_consulta` | `SELECT` exclusivo en `vw_alumnos_basico`, `vw_boleta_consulta`, `vw_resumen_asistencias` y `materias`. **Sin escritura** ni acceso directo a tablas sensibles o `usuarios_sistema`. |
| `auditor_inactivo` *(solo `usuarios_sistema`)* | `Inactivo123` | `rol_consulta` (`activo = FALSE`) | Registro aplicativo inactivo para pruebas de rechazo en `autenticar_usuario()`. |

---

## 6. Consultas SQL de verificación

### 6.1 Cifrado, descifrado y bcrypt (`admin`)
```bash
docker exec -it sistema_escolar_pg psql -U admin -d sistema_escolar
```
```sql
-- Almacenamiento cifrado opaco en BYTEA
SELECT id_alumno, matricula, left(encode(curp_cifrado, 'hex'), 36) AS curp_hex
FROM alumnos
ORDER BY id_alumno;

-- Descifrado autorizado AES-256
SELECT id_alumno, matricula, nombre_completo,
       pgp_sym_decrypt(curp_cifrado,     'ClaveMaestraEscolar_Dev2026!') AS curp,
       pgp_sym_decrypt(correo_cifrado,   'ClaveMaestraEscolar_Dev2026!') AS correo,
       pgp_sym_decrypt(telefono_cifrado, 'ClaveMaestraEscolar_Dev2026!') AS telefono
FROM alumnos
ORDER BY id_alumno;

-- Validación bcrypt y función autenticar_usuario()
SELECT username, rol, activo, left(password_hash, 29) AS prefijo_bcrypt,
       (password_hash = crypt('Admin123', password_hash)) AS valida_admin
FROM usuarios_sistema;

SELECT * FROM autenticar_usuario('admin', 'Admin123');
SELECT * FROM autenticar_usuario('auditor_inactivo', 'Inactivo123');
```

### 6.2 Control de acceso RBAC (`docente_demo` y `consulta_demo`)
```bash
# Docente: permitido sin PII vs denegado en PII / usuarios_sistema / DELETE
docker exec -it sistema_escolar_pg psql -U docente_demo -d sistema_escolar -c "SELECT matricula, nombre_completo FROM alumnos LIMIT 3; SELECT curp_cifrado FROM alumnos LIMIT 1; SELECT * FROM usuarios_sistema;"

# Consulta: permitido en vistas vs denegado en tablas base y escritura
docker exec -it sistema_escolar_pg psql -U consulta_demo -d sistema_escolar -c "SELECT * FROM vw_boleta_consulta LIMIT 3; SELECT * FROM alumnos LIMIT 1; DELETE FROM materias;"
```

---

## 7. Construcción y publicación en Docker Hub

Reemplaza `<tu_usuario>` por tu usuario de Docker Hub:

```bash
# Construir imagen
docker build -t sistema_escolar:v1 .

# Etiquetar para Docker Hub
docker tag sistema_escolar:v1 docker.io/<tu_usuario>/sistema_escolar:v1
docker tag sistema_escolar:v1 docker.io/<tu_usuario>/sistema_escolar:latest

# Iniciar sesión y publicar
docker login
docker push docker.io/<tu_usuario>/sistema_escolar:v1
docker push docker.io/<tu_usuario>/sistema_escolar:latest

# Ejecutar directamente desde la imagen publicada
docker run -d \
  --name sistema_escolar_hub \
  -e POSTGRES_DB=sistema_escolar \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=PostgresRootDev2026! \
  -p 5432:5432 \
  docker.io/<tu_usuario>/sistema_escolar:v1
```
