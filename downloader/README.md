# downloader

Worker for the tube download queue. One run claims up to `TUBE_CLAIM_LIMIT` queued jobs
from `/bff/tube/internal/download-jobs/claim`, downloads each with yt-dlp into
`$TUBE_CONTENT_ROOT/<domain>/<subject>/videos/`, and reports `downloading`, then `done`
(with the size and the `/<domain>/<subject>/videos/<file>` path the media signer accepts)
or `failed` to `/report`. It then exits.

| Variable | Meaning |
|---|---|
| `TUBE_BFF_URL` | required, base URL of tube-bff-api |
| `TUBE_WORKER_TOKEN_FILE` | optional, file holding the bearer token |
| `TUBE_CA_FILE`, `TUBE_CLIENT_CERT_FILE`, `TUBE_CLIENT_KEY_FILE` | optional, for an `https://` BFF URL |
| `TUBE_WORKER_ID` | defaults to the host name |
| `TUBE_CLAIM_LIMIT` | defaults to 2 |
| `TUBE_CONTENT_ROOT` | defaults to `/var/tube-content` |

Tests (standard library only): `cd downloader && python3 -m unittest -v test_tube_worker`.
