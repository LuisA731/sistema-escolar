-- =============================================================================
-- Archivo: sql/01_esquema.sql
-- Proyecto: sistema-escolar (PostgreSQL + Docker + pgcrypto)
-- Descripcion: Definicion del esquema relacional, extension pgcrypto,
--              indices, vistas seguras para RBAC y funcion de autenticacion.
-- Ejecucion: Idempotente. Se carga automaticamente en /docker-entrypoint-initdb.d/
--            dentro de la base de datos definida en POSTGRES_DB (sistema_escolar).
-- =============================================================================

-- 1. Habilitar extension criptografica pgcrypto
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 2. Tabla de alumnos (campos PII almacenados como BYTEA cifrado con PGP simetrico)
CREATE TABLE IF NOT EXISTS alumnos (
    id_alumno        SERIAL PRIMARY KEY,
    matricula        VARCHAR(20)  NOT NULL UNIQUE,
    nombre_completo  VARCHAR(150) NOT NULL,
    curp_cifrado     BYTEA        NOT NULL,
    correo_cifrado   BYTEA        NOT NULL,
    telefono_cifrado BYTEA        NOT NULL,
    fecha_nacimiento DATE         NOT NULL,
    fecha_registro   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE alumnos IS 'Catalogo de estudiantes con datos personales sensibles (CURP, correo, telefono) cifrados en BYTEA mediante pgcrypto.';
COMMENT ON COLUMN alumnos.curp_cifrado IS 'CURP cifrada con pgp_sym_encrypt (AES-256).';
COMMENT ON COLUMN alumnos.correo_cifrado IS 'Correo electronico cifrado con pgp_sym_encrypt (AES-256).';
COMMENT ON COLUMN alumnos.telefono_cifrado IS 'Numero telefonico cifrado con pgp_sym_encrypt (AES-256).';

-- 3. Tabla de materias
CREATE TABLE IF NOT EXISTS materias (
    id_materia     SERIAL PRIMARY KEY,
    clave_materia  VARCHAR(20)  NOT NULL UNIQUE,
    nombre_materia VARCHAR(120) NOT NULL,
    creditos       SMALLINT     NOT NULL CHECK (creditos > 0 AND creditos <= 20),
    docente        VARCHAR(150) NOT NULL
);

COMMENT ON TABLE materias IS 'Catalogo de asignaturas academicas impartidas en el periodo.';

-- 4. Tabla de calificaciones
CREATE TABLE IF NOT EXISTS calificaciones (
    id_calificacion        SERIAL PRIMARY KEY,
    id_alumno              INTEGER      NOT NULL REFERENCES alumnos(id_alumno) ON DELETE RESTRICT ON UPDATE CASCADE,
    id_materia             INTEGER      NOT NULL REFERENCES materias(id_materia) ON DELETE RESTRICT ON UPDATE CASCADE,
    periodo                VARCHAR(20)  NOT NULL,
    calificacion_final     NUMERIC(4,2) NOT NULL CHECK (calificacion_final >= 0.00 AND calificacion_final <= 10.00),
    observaciones_cifradas BYTEA,
    CONSTRAINT uq_calificacion_alumno_materia_periodo UNIQUE (id_alumno, id_materia, periodo)
);

COMMENT ON TABLE calificaciones IS 'Registro de calificaciones por alumno, materia y periodo con observaciones sensibles cifradas.';
COMMENT ON COLUMN calificaciones.observaciones_cifradas IS 'Observaciones academicas o disciplinarias cifradas con pgp_sym_encrypt.';

-- 5. Tabla de asistencias
CREATE TABLE IF NOT EXISTS asistencias (
    id_asistencia SERIAL PRIMARY KEY,
    id_alumno     INTEGER     NOT NULL REFERENCES alumnos(id_alumno) ON DELETE RESTRICT ON UPDATE CASCADE,
    id_materia    INTEGER     NOT NULL REFERENCES materias(id_materia) ON DELETE RESTRICT ON UPDATE CASCADE,
    fecha_clase   DATE        NOT NULL,
    estado        VARCHAR(15) NOT NULL CHECK (estado IN ('presente', 'ausente', 'retardo', 'justificado')),
    nota_cifrada  BYTEA,
    CONSTRAINT uq_asistencia_alumno_materia_fecha UNIQUE (id_alumno, id_materia, fecha_clase)
);

COMMENT ON TABLE asistencias IS 'Control de asistencias por clase con notas justificativas cifradas en BYTEA.';
COMMENT ON COLUMN asistencias.nota_cifrada IS 'Nota o motivo de justificante cifrado con pgp_sym_encrypt.';

-- 6. Tabla de usuarios del sistema (autenticacion aplicativa con bcrypt)
CREATE TABLE IF NOT EXISTS usuarios_sistema (
    id_usuario    SERIAL PRIMARY KEY,
    username      VARCHAR(50) NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    rol           VARCHAR(30) NOT NULL CHECK (rol IN ('rol_admin', 'rol_docente', 'rol_consulta')),
    activo        BOOLEAN     NOT NULL DEFAULT TRUE,
    creado_en     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE usuarios_sistema IS 'Cuentas aplicativas con hashes bcrypt (gen_salt(''bf'', 10)) y asignacion de rol RBAC.';
COMMENT ON COLUMN usuarios_sistema.password_hash IS 'Hash bcrypt generado con crypt(password, gen_salt(''bf'', 10)).';

-- 7. Indices de rendimiento en llaves foraneas y busquedas frecuentes
CREATE INDEX IF NOT EXISTS idx_calificaciones_alumno  ON calificaciones (id_alumno);
CREATE INDEX IF NOT EXISTS idx_calificaciones_materia ON calificaciones (id_materia);
CREATE INDEX IF NOT EXISTS idx_asistencias_alumno     ON asistencias (id_alumno);
CREATE INDEX IF NOT EXISTS idx_asistencias_materia    ON asistencias (id_materia);
CREATE INDEX IF NOT EXISTS idx_asistencias_fecha      ON asistencias (fecha_clase);

-- 8. Vistas restringidas para control de acceso basado en roles (principio de minimo privilegio)
-- Exponen unicamente campos academicos no sensibles, omitiendo PII cifrada y password_hash.
CREATE OR REPLACE VIEW vw_alumnos_basico AS
SELECT
    id_alumno,
    matricula,
    nombre_completo,
    fecha_nacimiento,
    fecha_registro
FROM alumnos;

COMMENT ON VIEW vw_alumnos_basico IS 'Vista segura de alumnos sin columnas PII cifradas (CURP, correo, telefono).';

CREATE OR REPLACE VIEW vw_boleta_consulta AS
SELECT
    c.id_calificacion,
    a.matricula,
    a.nombre_completo AS alumno,
    m.clave_materia,
    m.nombre_materia,
    m.creditos,
    m.docente,
    c.periodo,
    c.calificacion_final
FROM calificaciones c
JOIN alumnos a  ON a.id_alumno = c.id_alumno
JOIN materias m ON m.id_materia = c.id_materia;

COMMENT ON VIEW vw_boleta_consulta IS 'Vista de solo lectura de boletas sin observaciones cifradas.';

CREATE OR REPLACE VIEW vw_resumen_asistencias AS
SELECT
    asi.id_asistencia,
    a.matricula,
    a.nombre_completo AS alumno,
    m.clave_materia,
    m.nombre_materia,
    asi.fecha_clase,
    asi.estado
FROM asistencias asi
JOIN alumnos a  ON a.id_alumno = asi.id_alumno
JOIN materias m ON m.id_materia = asi.id_materia;

COMMENT ON VIEW vw_resumen_asistencias IS 'Vista de solo lectura de asistencias sin notas justificativas cifradas.';

-- 9. Funcion segura de autenticacion aplicativa (no expone password_hash)
CREATE OR REPLACE FUNCTION autenticar_usuario(
    p_username VARCHAR,
    p_password TEXT
)
RETURNS TABLE (
    id_usuario  INTEGER,
    username    VARCHAR,
    rol         VARCHAR,
    autenticado BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT
        u.id_usuario,
        u.username,
        u.rol,
        (u.activo AND u.password_hash = crypt(p_password, u.password_hash)) AS autenticado
    FROM usuarios_sistema u
    WHERE u.username = p_username;
END;
$$;

COMMENT ON FUNCTION autenticar_usuario(VARCHAR, TEXT) IS 'Verifica credenciales mediante bcrypt (crypt) y estado activo sin exponer el hash almacenado.';
