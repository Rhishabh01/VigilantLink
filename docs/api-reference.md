# API Reference

Base URL is configured in `background.js` as `BACKEND_URL`. All requests use JSON.

---

## Endpoints

### `POST /analyze`

Runs Phase 1 analysis. Kicks off Phase 2 as a background task.

**Request**

```json
{
  "url": "https://example.com/path?query=value"
}
```

`url` must be a valid `http://` or `https://` URL. Other schemes return HTTP 400.

**Response — Stage 1 (Phase 1 complete, Phase 2 pending)**

```json
{
  "s": 1,
  "id": "a3f8c12d9e01",
  "url": "https://example.com/path",
  "furl": "https://example.com/redirected",
  "hops": [
    { "u": "https://example.com/path", "c": 301 },
    { "u": "https://example.com/redirected", "c": 200 }
  ],
  "t": "Example Domain",
  "d": "This is an example page.",
  "img": "https://example.com/og.png",
  "fav": "https://example.com/favicon.ico",
  "ss": null,
  "sec": {
    "safe": true,
    "v": "green",
    "rs": 5,
    "tt": null,
    "vf": 0,
    "tv": 0,
    "age": null,
    "sr": false,
    "ts": false,
    "r": []
  },
  "ms": 312
}
```

**Response — Full cache hit (Phase 2 already cached)**

Same structure as Stage 2 below, returned immediately from `/analyze`.

---

### `GET /analyze/deep/{request_id}`

Poll endpoint. Returns the Phase 2 result when ready.

**Not ready**

```json
{
  "s": 0,
  "id": "a3f8c12d9e01"
}
```

**Ready — Stage 2**

```json
{
  "s": 2,
  "id": "a3f8c12d9e01",
  "url": "https://example.com/path",
  "furl": "https://example.com/redirected",
  "hops": [
    { "u": "https://example.com/path", "c": 301 },
    { "u": "https://example.com/redirected", "c": 200 }
  ],
  "t": "Example Domain",
  "d": "This is an example page.",
  "img": "https://example.com/og.png",
  "fav": "https://example.com/favicon.ico",
  "ss": "data:image/jpeg;base64,/9j/4AAQ...",
  "sec": {
    "safe": true,
    "v": "green",
    "rs": 8,
    "tt": null,
    "vf": 0,
    "tv": 70,
    "age": 542,
    "sr": false,
    "ts": false,
    "r": [],
    "gsb": false,
    "gsbt": null
  },
  "ms": 1204
}
```

---

### `GET /health`

```json
{ "status": "ok", "service": "VigilantLink" }
```

Used by Render health checks. Always returns HTTP 200 while the server is running.

### `GET /`

```json
{ "status": "VigilantLink backend running" }
```

---

## Response Field Reference

### Top-level fields

| Field | Type | Description |
|---|---|---|
| `s` | int | Stage: `0` = pending, `1` = Phase 1 complete, `2` = Phase 2 complete |
| `id` | string | 12-hex request ID. Used to poll `/analyze/deep/{id}` |
| `url` | string | Original URL submitted |
| `furl` | string | Final URL after redirect resolution |
| `hops` | array | Redirect chain. Each entry: `{ "u": url, "c": status_code }` |
| `t` | string\|null | Page title (OG or `<title>`) |
| `d` | string\|null | Page description (OG or `<meta name="description">`) |
| `img` | string\|null | OG image URL |
| `fav` | string\|null | Favicon URL |
| `ss` | string\|null | Screenshot as `data:image/jpeg;base64,...`. Only present in Stage 2 |
| `ms` | int | Total elapsed time in milliseconds |

### `sec` object

| Field | Type | Description |
|---|---|---|
| `safe` | bool | `true` if verdict is `green` |
| `v` | string | Verdict: `"green"`, `"yellow"`, or `"red"` |
| `rs` | int | Risk score (0–100) |
| `tt` | string\|null | Primary threat type label |
| `vf` | int | Backward compatible vendor flags count (calculated from PhishTank + OpenPhish) |
| `tv` | int | Backward compatible total vendors checked (always 2) |
| `age` | int\|null | SSL certificate age in days. `null` if unavailable |
| `sr` | bool | `true` if redirect chain depth exceeds threshold |
| `ts` | bool | `true` if typosquatting detected |
| `r` | array | Human-readable reason strings |
| `gsb` | bool | `true` if Google Safe Browsing match found. Stage 2 only |
| `gsbt` | string\|null | GSB threat type string. Stage 2 only |

---

## Error Responses

### HTTP 400 — Invalid URL scheme

```json
{
  "detail": "Unsupported scheme: ftp. Only http/https URLs are supported."
}
```

### HTTP 403 — Forbidden origin

```json
{
  "detail": "Forbidden: Access restricted to official Chrome Extension."
}
```

### HTTP 422 — Request validation error

Returned by FastAPI/Pydantic when the request body is malformed.

```json
{
  "detail": [
    {
      "loc": ["body", "url"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

### HTTP 429 — Rate limit exceeded

Returned by the leaky bucket middleware when a session exceeds 10 requests with a 2.0/s leak rate.

---

## Phase 2 Failure Fallback

If `run_phase2` raises an unhandled exception, the background task catches it and constructs a stage 2 response using Phase 1 data. The `reasons` array will contain:

```
"Deep scan unavailable — showing preliminary result"
```

`s` will be `2` so the extension stops polling. `gsb` and `gsbt` will be `false` and `null`.

---

## Polling Contract

The extension polls `GET /analyze/deep/{id}` every 1000ms.

- `s=0` → keep polling
- `s=2` → final result, stop polling
- HTTP 404 or 410 → session expired, stop polling
- Elapsed > 30000ms → timeout, fall back to Phase 1 result
