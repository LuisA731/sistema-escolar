# =============================================================================
# Dockerfile - sistema-escolar (PostgreSQL 16 + pgcrypto + RBAC)
# Construye una imagen lista para desarrollo, pruebas o publicacion en Docker Hub
# con los scripts de esquema, datos cifrados y seguridad preempaquetados.
# =============================================================================

FROM postgres:16-alpine

LABEL maintainer="Ingeniero de Seguridad de Base de Datos y DevOps" \
      org.opencontainers.image.title="sistema-escolar-db" \
      org.opencontainers.image.description="PostgreSQL 16 Alpine con pgcrypto (AES-256, bcrypt) y RBAC para sistema escolar" \
      org.opencontainers.image.version="1.0.0"

# Variables de entorno por defecto para desarrollo/pruebas
# IMPORTANTE: En entornos productivos deben inyectarse mediante secrets o --env-file
ENV POSTGRES_DB=sistema_escolar \
    POSTGRES_USER=postgres \
    POSTGRES_PASSWORD=PostgresRootDev2026! \
    TZ=America/Mexico_City

# Copiar scripts de inicializacion en orden alfabetico obligatorio (01 -> 02 -> 03)
COPY sql/01_esquema.sql /docker-entrypoint-initdb.d/01_esquema.sql
COPY sql/02_datos.sql /docker-entrypoint-initdb.d/02_datos.sql
COPY sql/03_seguridad.sql /docker-entrypoint-initdb.d/03_seguridad.sql

RUN chmod 644 /docker-entrypoint-initdb.d/*.sql

EXPOSE 5432

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 \
    CMD pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" || exit 1

CMD ["postgres", "-c", "password_encryption=scram-sha-256"]
