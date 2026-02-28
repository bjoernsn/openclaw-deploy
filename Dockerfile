# Extends the upstream OpenClaw image with database + data analysis tools
# so the agent can query PostgreSQL and process data without runtime installs.
ARG OPENCLAW_IMAGE=openclaw:local
FROM ${OPENCLAW_IMAGE}

USER root
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends \
       python3 python3-pip libpq5 postgresql-client jq \
    && pip3 install --break-system-packages \
       psycopg2-binary pandas numpy sqlalchemy \
    && apt-get purge -y python3-pip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /root/.cache
USER 1000:1000
