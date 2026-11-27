-- =============================================================================
-- Archivo: sql/03_seguridad.sql
-- Proyecto: sistema-escolar (PostgreSQL + Docker + pgcrypto)
-- Descripcion: Implementacion de control de acceso basado en roles (RBAC),
--              principio de minimo privilegio, revocacion de PUBLIC y
--              configuracion de cuentas PostgreSQL de prueba.
-- Ejecucion: Idempotente.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. CREACION IDEMPOTENTE DE ROLES DE GRUPO (NOLOGIN) Y USUARIOS (LOGIN)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    -- Roles funcionales (NOLOGIN)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rol_admin') THEN
        CREATE ROLE rol_admin NOLOGIN CREATEROLE;
    ELSE
        ALTER ROLE rol_admin NOLOGIN CREATEROLE;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rol_docente') THEN
        CREATE ROLE rol_docente NOLOGIN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rol_consulta') THEN
        CREATE ROLE rol_consulta NOLOGIN;
    END IF;

    -- Usuarios de base de datos (LOGIN) para pruebas y operacion
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'admin') THEN
        CREATE ROLE admin LOGIN PASSWORD 'Admin123' CREATEROLE INHERIT;
    ELSE
        ALTER ROLE admin WITH LOGIN PASSWORD 'Admin123' CREATEROLE INHERIT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'docente_demo') THEN
        CREATE ROLE docente_demo LOGIN PASSWORD 'Docente123' INHERIT;
    ELSE
        ALTER ROLE docente_demo WITH LOGIN PASSWORD 'Docente123' INHERIT;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consulta_demo') THEN
        CREATE ROLE consulta_demo LOGIN PASSWORD 'Consulta123' INHERIT;
    ELSE
        ALTER ROLE consulta_demo WITH LOGIN PASSWORD 'Consulta123' INHERIT;
    END IF;
END $$;

-- Asignar membresias de rol
GRANT rol_admin    TO admin;
GRANT rol_docente  TO docente_demo;
GRANT rol_consulta TO consulta_demo;

-- -----------------------------------------------------------------------------
-- 2. REVOCACION ESTRICTA DE PRIVILEGIOS POR DEFECTO (PUBLIC)
-- -----------------------------------------------------------------------------
DO $$
DECLARE
    v_db TEXT := current_database();
BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', v_db);
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO rol_admin, rol_docente, rol_consulta', v_db);
END $$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- Evitar que futuros objetos otorguen permisos implicitos a PUBLIC
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC;

-- -----------------------------------------------------------------------------
-- 3. PRIVILEGIOS PARA rol_admin (Administracion general y gestion de usuarios)
-- -----------------------------------------------------------------------------
GRANT USAGE, CREATE ON SCHEMA public TO rol_admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO rol_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO rol_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO rol_admin;

-- -----------------------------------------------------------------------------
-- 4. PRIVILEGIOS PARA rol_docente (Minimo privilegio para gestion academica)
--    - Consulta de alumnos (solo columnas no PII) y vistas seguras
--    - Consulta de materias
--    - Lectura/escritura de calificaciones y asistencias
--    - SIN acceso a CURP/correo/telefono ni a usuarios_sistema (hashes)
-- -----------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO rol_docente;

-- Vistas seguras y catalogo de materias
GRANT SELECT ON vw_alumnos_basico, vw_boleta_consulta, vw_resumen_asistencias, materias TO rol_docente;

-- Acceso por columna a alumnos (excluye curp_cifrado, correo_cifrado, telefono_cifrado)
REVOKE ALL ON alumnos FROM rol_docente;
GRANT SELECT (id_alumno, matricula, nombre_completo, fecha_nacimiento, fecha_registro)
    ON alumnos TO rol_docente;

-- Lectura y escritura en calificaciones y asistencias (sin DELETE)
REVOKE ALL ON calificaciones, asistencias FROM rol_docente;
GRANT SELECT, INSERT, UPDATE ON calificaciones, asistencias TO rol_docente;
GRANT USAGE, SELECT ON SEQUENCE calificaciones_id_calificacion_seq, asistencias_id_asistencia_seq TO rol_docente;

-- Permitir cifrado/descifrado PGP para observaciones_cifradas y nota_cifrada
GRANT EXECUTE ON FUNCTION
    pgp_sym_encrypt(text, text),
    pgp_sym_encrypt(text, text, text),
    pgp_sym_decrypt(bytea, text),
    pgp_sym_decrypt(bytea, text, text)
    TO rol_docente;

-- Bloqueo explicito sobre tabla de credenciales
REVOKE ALL ON usuarios_sistema FROM rol_docente;

-- -----------------------------------------------------------------------------
-- 5. PRIVILEGIOS PARA rol_consulta (Solo lectura restringida)
--    - Unicamente vistas seguras y catalogo de materias
--    - SIN escritura ni acceso directo a tablas sensibles ni usuarios_sistema
-- -----------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO rol_consulta;

REVOKE ALL ON alumnos, calificaciones, asistencias, usuarios_sistema FROM rol_consulta;
GRANT SELECT ON vw_alumnos_basico, vw_boleta_consulta, vw_resumen_asistencias, materias TO rol_consulta;
