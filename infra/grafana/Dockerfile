# syntax=docker/dockerfile:1
# ExtorQ Grafana image (owner: D1). Built by the compose service "grafana" (profile full).
#
# * Pinned base (tag + digest) and the official ClickHouse datasource plugin installed at
#   BUILD time into a root-owned directory; the server never downloads plugins at runtime
#   (preinstall disabled, plugin admin disabled, signature keys not fetched).
# * Provisioning (datasource + dashboards) is baked in and read-only.
# * Security settings are environment variables so they are visible with `docker inspect`
#   and cannot be changed from the UI. Secrets (admin password, datasource password) are
#   compose file secrets read at startup: see infra/grafana/README.md.
FROM grafana/grafana:13.1.10@sha256:467fa061e60b09f4011c6f84620b9ec8805b077f85dfb2b76c5bdbc35b1b1a8f

ARG CLICKHOUSE_PLUGIN_VERSION=4.23.5

ENV GF_PATHS_PLUGINS=/usr/share/grafana/extorq-plugins

USER root
# `grafana cli` verifies the archive checksum published by grafana.com for this exact
# version; Grafana verifies the plugin signature (Grafana Labs) every time it loads it.
RUN mkdir -p "${GF_PATHS_PLUGINS}" \
 && grafana cli --pluginsDir "${GF_PATHS_PLUGINS}" \
        plugins install grafana-clickhouse-datasource "${CLICKHOUSE_PLUGIN_VERSION}" \
 && chown -R root:root "${GF_PATHS_PLUGINS}" \
 && chmod -R u=rwX,go=rX "${GF_PATHS_PLUGINS}" \
 && rm -f /etc/grafana/provisioning/*/*.yaml /etc/grafana/provisioning/*/*.yml

COPY --chown=root:root provisioning/datasources/extorq-clickhouse.yaml /etc/grafana/provisioning/datasources/
COPY --chown=root:root provisioning/dashboards/extorq.yaml /etc/grafana/provisioning/dashboards/
COPY --chown=root:root dashboards/ /etc/grafana/dashboards/extorq/
# Readable by the runtime user (uid 472), writable only by root.
RUN chmod -R u=rwX,go=rX /etc/grafana/provisioning /etc/grafana/dashboards

# Hardening (grafana.ini equivalents; environment variables take precedence over the file).
ENV GF_LOG_MODE=console \
    GF_SERVER_ENABLE_GZIP=true \
    GF_SECURITY_DISABLE_GRAVATAR=true \
    GF_SECURITY_ALLOW_EMBEDDING=false \
    GF_SECURITY_COOKIE_SAMESITE=strict \
    GF_SECURITY_COOKIE_SECURE=false \
    GF_SECURITY_CONTENT_SECURITY_POLICY=true \
    GF_SECURITY_X_CONTENT_TYPE_OPTIONS=true \
    GF_SECURITY_DISABLE_BRUTE_FORCE_LOGIN_PROTECTION=false \
    GF_AUTH_ANONYMOUS_ENABLED=false \
    GF_AUTH_DISABLE_LOGIN_FORM=false \
    GF_AUTH_LOGIN_MAXIMUM_INACTIVE_LIFETIME_DURATION=8h \
    GF_AUTH_LOGIN_MAXIMUM_LIFETIME_DURATION=24h \
    GF_USERS_ALLOW_SIGN_UP=false \
    GF_USERS_ALLOW_ORG_CREATE=false \
    GF_USERS_VIEWERS_CAN_EDIT=false \
    GF_ANALYTICS_REPORTING_ENABLED=false \
    GF_ANALYTICS_CHECK_FOR_UPDATES=false \
    GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false \
    GF_ANALYTICS_FEEDBACK_LINKS_ENABLED=false \
    GF_NEWS_NEWS_FEED_ENABLED=false \
    GF_SNAPSHOTS_ENABLED=false \
    GF_SNAPSHOTS_EXTERNAL_ENABLED=false \
    GF_PUBLIC_DASHBOARDS_ENABLED=false \
    GF_PLUGINS_PREINSTALL_DISABLED=true \
    GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false \
    GF_PLUGINS_PUBLIC_KEY_RETRIEVAL_DISABLED=true \
    GF_UNIFIED_ALERTING_ENABLED=false \
    GF_DASHBOARDS_MIN_REFRESH_INTERVAL=30s \
    GF_DATE_FORMATS_DEFAULT_TIMEZONE=UTC

USER 472

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:3000/api/health || exit 1
