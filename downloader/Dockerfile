# syntax=docker/dockerfile:1.7
# Image for the tube download worker (tube_worker.py + yt-dlp).
# Build from this directory:  docker build -t hugmesh/tube-downloader downloader/
#
# The image holds no credential. The worker reads its bearer token from the file named by
# TUBE_WORKER_TOKEN_FILE at run time, which a deployment mounts from a Secret.
FROM python:3.13-slim

ARG YT_DLP_VERSION=2026.8.19

RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "yt-dlp==${YT_DLP_VERSION}"

COPY tube_worker.py /usr/local/bin/tube_worker.py

# Non-root. The content volume the deployment mounts must be writable by this uid.
RUN useradd --system --uid 10001 --no-create-home tube
USER 10001

ENTRYPOINT ["python3", "/usr/local/bin/tube_worker.py"]
