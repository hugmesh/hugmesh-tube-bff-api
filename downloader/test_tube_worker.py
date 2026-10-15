import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import tube_worker as tw

HERE = os.path.dirname(os.path.abspath(__file__))


class FakeBff:
    """A claim/report server that records every request it receives."""

    def __init__(self, jobs, claim_status=200):
        self.jobs = jobs
        self.claim_status = claim_status
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append((self.path, body, self.headers.get("Authorization")))
                status, reply = 200, {}
                if self.path == tw.CLAIM_PATH:
                    status, reply = outer.claim_status, {"jobs": outer.jobs}
                data = json.dumps(reply).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def reports(self):
        return [body for path, body, _ in self.requests if path == tw.REPORT_PATH]


class StubDownloader:
    def __init__(self, fail_for=(), name=None):
        self.calls = []
        self.fail_for = set(fail_for)
        self.name = name

    def download(self, video_id, dest_dir):
        self.calls.append((video_id, dest_dir))
        if video_id in self.fail_for:
            raise tw.WorkerError("stub download failed for " + video_id)
        name = self.name or video_id + ".mp4"
        with open(os.path.join(dest_dir, name), "wb") as fh:
            fh.write(b"x" * 11)
        return name


def job(job_id, video_id, domain="acme", subject="alice"):
    return {"id": job_id, "domain": domain, "userSubject": subject, "videoId": video_id}


class WorkerFlowTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)

    def run_worker(self, bff, downloader, token="tok"):
        client = tw.BffClient(bff.url, token=token)
        return tw.run_once(client, downloader, "worker-7", 3, self.root.name)

    def test_claims_downloads_and_reports_done_with_size_and_path(self):
        bff = FakeBff([job("j1", "abcDEF12345")])
        self.addCleanup(bff.close)
        results = self.run_worker(bff, StubDownloader())
        self.assertEqual(results, ["done"])
        self.assertEqual(bff.requests[0][:2], (tw.CLAIM_PATH, {"workerId": "worker-7", "limit": 3}))
        self.assertEqual([r["result"] for r in bff.reports()], ["downloading", "done"])
        done = bff.reports()[1]
        self.assertEqual(done["jobId"], "j1")
        self.assertEqual(done["workerId"], "worker-7")
        self.assertEqual(done["bytes"], 11)
        self.assertEqual(done["contentPath"], "/acme/alice/videos/abcDEF12345.mp4")
        self.assertTrue(os.path.isfile(
            os.path.join(self.root.name, "acme", "alice", "videos", "abcDEF12345.mp4")))

    def test_every_request_carries_the_bearer_token(self):
        bff = FakeBff([job("j1", "vid1")])
        self.addCleanup(bff.close)
        self.run_worker(bff, StubDownloader(), token="s3cret")
        self.assertEqual({auth for _, _, auth in bff.requests}, {"Bearer s3cret"})

    def test_empty_claim_downloads_and_reports_nothing(self):
        bff = FakeBff([])
        self.addCleanup(bff.close)
        stub = StubDownloader()
        self.assertEqual(self.run_worker(bff, stub), [])
        self.assertEqual(stub.calls, [])
        self.assertEqual(bff.reports(), [])

    def test_a_failed_download_is_reported_and_the_batch_continues(self):
        bff = FakeBff([job("j1", "bad"), job("j2", "good")])
        self.addCleanup(bff.close)
        results = self.run_worker(bff, StubDownloader(fail_for=["bad"]))
        self.assertEqual(results, ["failed", "done"])
        failed = [r for r in bff.reports() if r["result"] == "failed"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["jobId"], "j1")
        self.assertIn("stub download failed for bad", failed[0]["error"])
        self.assertTrue(any(r["jobId"] == "j2" and r["result"] == "done" for r in bff.reports()))

    def test_unsafe_owner_is_failed_without_downloading_or_writing(self):
        bff = FakeBff([job("j1", "vid1", subject="../escape"), job("j2", "vid2", domain="a/b")])
        self.addCleanup(bff.close)
        stub = StubDownloader()
        self.assertEqual(self.run_worker(bff, stub), ["failed", "failed"])
        self.assertEqual(stub.calls, [])
        self.assertEqual(os.listdir(self.root.name), [])
        self.assertEqual({r["result"] for r in bff.reports()}, {"failed"})

    def test_unsafe_video_id_is_failed_without_downloading(self):
        bff = FakeBff([job("j1", "x;rm -rf")])
        self.addCleanup(bff.close)
        stub = StubDownloader()
        self.assertEqual(self.run_worker(bff, stub), ["failed"])
        self.assertEqual(stub.calls, [])

    def test_unsafe_file_name_from_the_downloader_is_failed(self):
        bff = FakeBff([job("j1", "vid1")])
        self.addCleanup(bff.close)
        self.assertEqual(self.run_worker(bff, StubDownloader(name="a b.mp4")), ["failed"])
        self.assertNotIn("done", [r["result"] for r in bff.reports()])

    def test_reported_error_fits_the_server_limit(self):
        bff = FakeBff([job("j1", "vid1")])
        self.addCleanup(bff.close)

        class Boom:
            def download(self, video_id, dest_dir):
                raise RuntimeError("z" * 5000)

        self.run_worker(bff, Boom())
        error = [r for r in bff.reports() if r["result"] == "failed"][0]["error"]
        self.assertLessEqual(len(error), 2048)

    def test_claim_failure_makes_main_exit_nonzero(self):
        bff = FakeBff([], claim_status=403)
        self.addCleanup(bff.close)
        env = {"TUBE_BFF_URL": bff.url, "TUBE_CONTENT_ROOT": self.root.name}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(tw.main(), 1)

    def test_main_succeeds_on_an_empty_queue(self):
        bff = FakeBff([])
        self.addCleanup(bff.close)
        env = {"TUBE_BFF_URL": bff.url, "TUBE_CONTENT_ROOT": self.root.name}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(tw.main(), 0)

    def test_token_is_read_from_the_file_named_by_the_environment(self):
        path = os.path.join(self.root.name, "token")
        with open(path, "w") as fh:
            fh.write("from-file\n")
        client = tw.build_client({"TUBE_BFF_URL": "http://bff:8080", "TUBE_WORKER_TOKEN_FILE": path})
        self.assertEqual(client.token, "from-file")


class YtDlpDownloaderTest(unittest.TestCase):
    def fake_run(self, returncode=0, stdout="", stderr=""):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

        return run, calls

    def test_video_id_is_passed_after_the_option_terminator(self):
        run, calls = self.fake_run(stdout="/data/acme/alice/videos/abc.mp4\n")
        name = tw.YtDlpDownloader(run=run).download("abc", "/data/acme/alice/videos")
        self.assertEqual(name, "abc.mp4")
        argv = calls[0]
        self.assertEqual(argv[-2:], ["--", "https://www.youtube.com/watch?v=abc"])
        self.assertEqual(argv[argv.index("--paths") + 1], "/data/acme/alice/videos")
        self.assertIn("--no-playlist", argv)

    def test_a_video_id_that_could_be_an_option_is_rejected_before_running(self):
        run, calls = self.fake_run()
        with self.assertRaises(tw.WorkerError):
            tw.YtDlpDownloader(run=run).download("--exec=evil", "/d")
        self.assertEqual(calls, [])

    def test_nonzero_exit_raises_with_the_last_stderr_line(self):
        run, _ = self.fake_run(returncode=1, stderr="noise\nERROR: video unavailable\n")
        with self.assertRaises(tw.WorkerError) as ctx:
            tw.YtDlpDownloader(run=run).download("abc", "/d")
        self.assertIn("video unavailable", str(ctx.exception))

    def test_no_output_line_raises(self):
        run, _ = self.fake_run(stdout="")
        with self.assertRaises(tw.WorkerError):
            tw.YtDlpDownloader(run=run).download("abc", "/d")


class DockerfileTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(HERE, "Dockerfile"), encoding="utf-8") as fh:
            self.lines = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
        self.text = "\n".join(self.lines)

    def test_runs_as_a_non_root_user(self):
        users = [ln.split()[1] for ln in self.lines if ln.startswith("USER ")]
        self.assertTrue(users)
        self.assertNotIn(users[-1], ("root", "0"))

    def test_yt_dlp_is_pinned_to_an_exact_version(self):
        self.assertRegex(self.text, r"ARG YT_DLP_VERSION=\d{4}\.\d+\.\d+")
        self.assertIn('"yt-dlp==${YT_DLP_VERSION}"', self.text)

    def test_carries_no_secret_inputs(self):
        self.assertNotRegex(self.text, r"(?i)(token|secret|password|key)\s*=\s*\S")
        self.assertNotIn("--mount=type=secret", self.text)

    def test_entrypoint_runs_the_worker_that_is_copied_in(self):
        self.assertIn("COPY tube_worker.py /usr/local/bin/tube_worker.py", self.text)
        self.assertRegex(self.text, r'ENTRYPOINT \["python3", "/usr/local/bin/tube_worker.py"\]')


if __name__ == "__main__":
    unittest.main()
