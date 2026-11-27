-- =============================================================================
-- Archivo: sql/02_datos.sql
-- Proyecto: sistema-escolar (PostgreSQL + Docker + pgcrypto)
-- Descripcion: Carga inicial idempotente de datos de prueba con cifrado
--              simetrico AES-256 (pgp_sym_encrypt) y hashing bcrypt (coste 10).
-- Nota sobre clave de cifrado:
--   Lee la variable de configuracion PostgreSQL `app.encryption_key` (inyectada
--   desde docker-compose.yml via APP_ENCRYPTION_KEY). Si no esta definida en
--   ejecuciones locales manuales, utiliza la clave de desarrollo por defecto:
--     ClaveMaestraEscolar_Dev2026!
-- =============================================================================

DO $$
DECLARE
    v_key TEXT := COALESCE(
        NULLIF(current_setting('app.encryption_key', true), ''),
        'ClaveMaestraEscolar_Dev2026!'
    );
BEGIN
    -- -------------------------------------------------------------------------
    -- 1. ALUMNOS (6 registros con CURP, correo y telefono cifrados en BYTEA)
    -- -------------------------------------------------------------------------
    INSERT INTO alumnos (
        matricula,
        nombre_completo,
        curp_cifrado,
        correo_cifrado,
        telefono_cifrado,
        fecha_nacimiento
    ) VALUES
        (
            'A2026001',
            'Ana Sofia Mendoza Ruiz',
            pgp_sym_encrypt('MERA040512HDFNRN09', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('ana.mendoza@escuela.edu.mx', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('+52 55 1234 5601', v_key, 'cipher-algo=aes256'),
            '2004-05-12'
        ),
        (
            'A2026002',
            'Carlos Eduardo Ramirez Vega',
            pgp_sym_encrypt('RAVC031120HMCGDL04', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('carlos.ramirez@escuela.edu.mx', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('+52 33 2345 6702', v_key, 'cipher-algo=aes256'),
            '2003-11-20'
        ),
        (
            'A2026003',
            'Valeria Torres Castellanos',
            pgp_sym_encrypt('TOCV050208MNLMTY01', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('valeria.torres@escuela.edu.mx', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('+52 81 3456 7803', v_key, 'cipher-algo=aes256'),
            '2005-02-08'
        ),
        (
            'A2026004',
            'Diego Alejandro Morales Silva',
            pgp_sym_encrypt('MOSD040819HPUPLA07', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('diego.morales@escuela.edu.mx', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('+52 22 4567 8904', v_key, 'cipher-algo=aes256'),
            '2004-08-19'
        ),
        (
            'A2026005',
            'Fernanda Lucia Herrera Ortiz',
            pgp_sym_encrypt('HEOF050625MDFQRO02', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('fernanda.herrera@escuela.edu.mx', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('+52 44 5678 9005', v_key, 'cipher-algo=aes256'),
            '2005-06-25'
        ),
        (
            'A2026006',
            'Mateo Julian Navarro Paredes',
            pgp_sym_encrypt('NAPM040130HGTTOL08', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('mateo.navarro@escuela.edu.mx', v_key, 'cipher-algo=aes256'),
            pgp_sym_encrypt('+52 72 6789 0106', v_key, 'cipher-algo=aes256'),
            '2004-01-30'
        )
    ON CONFLICT (matricula) DO NOTHING;

    -- -------------------------------------------------------------------------
    -- 2. MATERIAS (5 asignaturas)
    -- -------------------------------------------------------------------------
    INSERT INTO materias (clave_materia, nombre_materia, creditos, docente) VALUES
        ('BD201',   'Seguridad en Bases de Datos',         8, 'Dra. Patricia Salinas Cruz'),
        ('SEG301',  'Criptografia Aplicada',               8, 'Mtro. Javier Dominguez Leon'),
        ('RED202',  'Seguridad en Redes y Perimetro',      7, 'Ing. Roberto Fuentes Aguilar'),
        ('PROG102', 'Desarrollo Seguro de Aplicaciones',   8, 'Mtra. Laura Paredes Gomez'),
        ('MAT101',  'Matematicas Discretas para Ciberseg', 6, 'Dr. Hector Ibarra Molina')
    ON CONFLICT (clave_materia) DO NOTHING;

    -- -------------------------------------------------------------------------
    -- 3. CALIFICACIONES (12 registros con observaciones cifradas)
    -- -------------------------------------------------------------------------
    INSERT INTO calificaciones (
        id_alumno, id_materia, periodo, calificacion_final, observaciones_cifradas
    )
    SELECT a.id_alumno, m.id_materia, v.periodo, v.calificacion,
           pgp_sym_encrypt(v.observacion, v_key, 'cipher-algo=aes256')
    FROM (
        VALUES
            ('A2026001', 'BD201',   '2026-1', 9.50, 'Desempeno sobresaliente en practicas de pgcrypto y RBAC.'),
            ('A2026001', 'SEG301',  '2026-1', 9.20, 'Excelente analisis de gestion de llaves simetricas.'),
            ('A2026002', 'BD201',   '2026-1', 8.40, 'Cumple con entregas; reforzar politicas de auditoria.'),
            ('A2026002', 'RED202',  '2026-1', 7.80, 'Requiere apoyo en configuracion de reglas de firewall.'),
            ('A2026003', 'BD201',   '2026-1', 9.80, 'Mejor proyecto final de endurecimiento PostgreSQL.'),
            ('A2026003', 'PROG102', '2026-1', 9.10, 'Buen manejo de consultas parametrizadas anti-SQLi.'),
            ('A2026004', 'SEG301',  '2026-1', 6.90, 'Aprobado en limite; solicito tutoria academica.'),
            ('A2026004', 'MAT101',  '2026-1', 7.50, 'Mejora constante en teoria de numeros modular.'),
            ('A2026005', 'BD201',   '2026-1', 8.90, 'Participacion activa en laboratorio de hardening.'),
            ('A2026005', 'RED202',  '2026-1', 9.00, 'Buen diagnostico de trafico TLS.'),
            ('A2026006', 'PROG102', '2026-1', 8.20, 'Implementacion correcta de control de acceso.'),
            ('A2026006', 'MAT101',  '2026-1', 8.60, 'Solida resolucion de ejercicios de algebra booleana.')
    ) AS v(matricula, clave_materia, periodo, calificacion, observacion)
    JOIN alumnos a  ON a.matricula = v.matricula
    JOIN materias m ON m.clave_materia = v.clave_materia
    ON CONFLICT (id_alumno, id_materia, periodo) DO NOTHING;

    -- -------------------------------------------------------------------------
    -- 4. ASISTENCIAS (15 registros cubriendo todos los estados + notas cifradas)
    -- -------------------------------------------------------------------------
    INSERT INTO asistencias (
        id_alumno, id_materia, fecha_clase, estado, nota_cifrada
    )
    SELECT a.id_alumno, m.id_materia, v.fecha::DATE, v.estado,
           pgp_sym_encrypt(v.nota, v_key, 'cipher-algo=aes256')
    FROM (
        VALUES
            ('A2026001', 'BD201',   '2026-11-02', 'presente',    'Asistencia puntual a sesion de laboratorio.'),
            ('A2026001', 'BD201',   '2026-11-04', 'presente',    'Participo en ejercicio de cifrado en vivo.'),
            ('A2026002', 'BD201',   '2026-11-02', 'retardo',     'Ingreso 12 minutos tarde por trafico.'),
            ('A2026002', 'BD201',   '2026-11-04', 'justificado', 'Presento receta medica oficial folio IMSS-8821.'),
            ('A2026003', 'BD201',   '2026-11-02', 'presente',    'Sin incidencias.'),
            ('A2026003', 'PROG102', '2026-11-05', 'presente',    'Entrega de avance de codigo seguro.'),
            ('A2026004', 'SEG301',  '2026-11-03', 'ausente',     'Falta no justificada; se envio aviso a tutoria.'),
            ('A2026004', 'SEG301',  '2026-11-05', 'retardo',     'Ingreso 15 minutos despues del pase de lista.'),
            ('A2026005', 'BD201',   '2026-11-02', 'presente',    'Sin incidencias.'),
            ('A2026005', 'RED202',  '2026-11-06', 'justificado', 'Comision institucional autorizada por coordinacion.'),
            ('A2026006', 'PROG102', '2026-11-05', 'presente',    'Sin incidencias.'),
            ('A2026006', 'MAT101',  '2026-11-07', 'ausente',     'Ausencia reportada por alumno via correo.'),
            ('A2026001', 'SEG301',  '2026-11-03', 'presente',    'Revision de practica de bcrypt.'),
            ('A2026002', 'RED202',  '2026-11-06', 'presente',    'Practica de segmentacion de red.'),
            ('A2026003', 'BD201',   '2026-11-09', 'presente',    'Validacion final de roles y privilegios.')
    ) AS v(matricula, clave_materia, fecha, estado, nota)
    JOIN alumnos a  ON a.matricula = v.matricula
    JOIN materias m ON m.clave_materia = v.clave_materia
    ON CONFLICT (id_alumno, id_materia, fecha_clase) DO NOTHING;

    -- -------------------------------------------------------------------------
    -- 5. USUARIOS DEL SISTEMA (hashes bcrypt con gen_salt('bf', 10))
    -- -------------------------------------------------------------------------
    INSERT INTO usuarios_sistema (username, password_hash, rol, activo) VALUES
        ('admin',            crypt('Admin123',    gen_salt('bf', 10)), 'rol_admin',    TRUE),
        ('docente_demo',     crypt('Docente123',  gen_salt('bf', 10)), 'rol_docente',  TRUE),
        ('consulta_demo',    crypt('Consulta123', gen_salt('bf', 10)), 'rol_consulta', TRUE),
        ('auditor_inactivo', crypt('Inactivo123', gen_salt('bf', 10)), 'rol_consulta', FALSE)
    ON CONFLICT (username) DO NOTHING;
END $$;
