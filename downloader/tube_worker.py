#!/usr/bin/env python3
"""Download worker for the tube download queue.

One run of this script drains one batch: it claims queued jobs from tube-bff-api
(POST /bff/tube/internal/download-jobs/claim), downloads each video, and reports the
result (POST /bff/tube/internal/download-jobs/report). It is meant to be started by a
CronJob and to exit; it does not loop.

Standard library only. The downloader is injected, so the claim/download/report flow is
tested with a stub; YtDlpDownloader is the real one and shells out to yt-dlp.
"""
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

CLAIM_PATH = "/bff/tube/internal/download-jobs/claim"
REPORT_PATH = "/bff/tube/internal/download-jobs/report"

# The BFF signs media paths of the form /<domain>/<subject>/<rest> whose segments match
# [A-Za-z0-9._-]+ with no "..": TubeMediaController.PATH_PATTERN. A job whose owner
# does not fit that shape could never be served, so it is failed instead of written.
SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
VIDEO_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# ReportRequest.error is @Size(max = 2048).
MAX_ERROR = 2000


class WorkerError(Exception):
    """A job-level failure whose message is safe to report back."""


def _segment_ok(value):
    return isinstance(value, str) and bool(SEGMENT.match(value)) and ".." not in value


class BffClient:
    def __init__(self, base_url, token=None, context=None, timeout=30):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.context = context
        self.timeout = timeout

    def _post(self, path, body):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(
            self.base_url + path, data=json.dumps(body).encode("utf-8"),
            headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as resp:
            return json.loads(resp.read().decode("utf-8") or "null")

    def claim(self, worker_id, limit):
        reply = self._post(CLAIM_PATH, {"workerId": worker_id, "limit": limit})
        return (reply or {}).get("jobs") or []

    def report(self, job_id, worker_id, result, size=0, content_path=None, error=None):
        body = {"jobId": job_id, "workerId": worker_id, "result": result, "bytes": size}
        if content_path is not None:
            body["contentPath"] = content_path
        if error is not None:
            body["error"] = error[:MAX_ERROR]
        return self._post(REPORT_PATH, body)


class YtDlpDownloader:
    """Fetch one video with yt-dlp into dest_dir and return the file name it wrote."""

    def __init__(self, binary="yt-dlp", run=subprocess.run):
        self.binary = binary
        self.run = run

    def argv(self, video_id, dest_dir):
        return [self.binary, "--no-playlist", "--no-progress",
                "--paths", dest_dir,
                "--output", "%(id)s.%(ext)s",
                "--print", "after_move:filename",
                "--", "https://www.youtube.com/watch?v=" + video_id]

    def download(self, video_id, dest_dir):
        if not VIDEO_ID.match(video_id or ""):
            raise WorkerError("video id has an unsupported shape")
        done = self.run(self.argv(video_id, dest_dir), capture_output=True, text=True)
        if done.returncode != 0:
            tail = (done.stderr or "").strip().splitlines()[-1:] or ["no output"]
            raise WorkerError("yt-dlp exited %d: %s" % (done.returncode, tail[0]))
        lines = (done.stdout or "").strip().splitlines()
        if not lines:
            raise WorkerError("yt-dlp reported no output file")
        return os.path.basename(lines[-1])


def process_job(job, client, downloader, worker_id, content_root):
    """Download one claimed job and report it. Returns the result string reported."""
    job_id = job.get("id")
    try:
        domain, subject, video_id = job.get("domain"), job.get("userSubject"), job.get("videoId")
        if not (_segment_ok(domain) and _segment_ok(subject)):
            raise WorkerError("job owner cannot be mapped to a safe content path")
        if not (isinstance(video_id, str) and VIDEO_ID.match(video_id)):
            raise WorkerError("video id has an unsupported shape")
        dest_dir = os.path.join(content_root, domain, subject, "videos")
        os.makedirs(dest_dir, exist_ok=True)
        client.report(job_id, worker_id, "downloading")
        name = downloader.download(video_id, dest_dir)
        if not _segment_ok(name):
            raise WorkerError("downloader returned an unsafe file name")
        size = os.path.getsize(os.path.join(dest_dir, name))
        client.report(job_id, worker_id, "done", size=size,
                      content_path="/%s/%s/videos/%s" % (domain, subject, name))
        return "done"
    except Exception as exc:  # a failing job must not stop the rest of the batch
        message = str(exc) if isinstance(exc, WorkerError) else "%s: %s" % (type(exc).__name__, exc)
        try:
            client.report(job_id, worker_id, "failed", error=message)
        except Exception as report_exc:
            print("report failed for job %s: %s" % (job_id, report_exc), file=sys.stderr)
        return "failed"


def run_once(client, downloader, worker_id, limit, content_root):
    """Claim one batch and process it. Returns the list of per-job results."""
    return [process_job(job, client, downloader, worker_id, content_root)
            for job in client.claim(worker_id, limit)]


def _env_int(name, default):
    raw = os.environ.get(name)
    return int(raw) if raw else default


def build_client(env=os.environ):
    base = env.get("TUBE_BFF_URL")
    if not base:
        raise SystemExit("TUBE_BFF_URL is required")
    token = None
    token_file = env.get("TUBE_WORKER_TOKEN_FILE")
    if token_file:
        with open(token_file, encoding="utf-8") as fh:
            token = fh.read().strip()
    context = None
    if base.startswith("https://"):
        context = ssl.create_default_context(cafile=env.get("TUBE_CA_FILE") or None)
        if env.get("TUBE_CLIENT_CERT_FILE"):
            context.load_cert_chain(env["TUBE_CLIENT_CERT_FILE"], env.get("TUBE_CLIENT_KEY_FILE"))
    return BffClient(base, token=token, context=context)


def main():
    client = build_client()
    worker_id = os.environ.get("TUBE_WORKER_ID") or socket.gethostname()
    limit = max(1, _env_int("TUBE_CLAIM_LIMIT", 2))
    content_root = os.environ.get("TUBE_CONTENT_ROOT", "/var/tube-content")
    try:
        results = run_once(client, YtDlpDownloader(), worker_id, limit, content_root)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print("claim failed: %s" % exc, file=sys.stderr)
        return 1
    print("claimed %d, done %d, failed %d" % (
        len(results), results.count("done"), results.count("failed")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
