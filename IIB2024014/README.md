# Manas Singh - IIB2024014

**Category:** OS command injection

**Variant:** In-band (command output returned)

**Implemented primary mitigation:** Avoid the shell and OS command; calculate the checksum with Python's `hashlib`. An exact filename allow-list is an additional implemented control.

The complete project, report, screenshots, exact payload, and tests are in [os-injection-lab](os-injection-lab/).

```bash
cd IIB2024014/os-injection-lab
docker compose up --build -d --wait
```

Open http://127.0.0.1:8080. Use **Normal filename**, then **Injection payload**, and run the comparison for each. The same injected input returns a harmless marker in the vulnerable route and HTTP 422 in the secure route.

This intentionally vulnerable teaching application is published as source code. Keep the running service bound to localhost using the provided Compose configuration.

## Ownership

| Member | Roll number | Category | Variant |
|---|---|---|---|
| Manas Singh | IIB2024014 | OS command injection | In-band |

## Report and video

- [Technical report and viva preparation](os-injection-lab/OS-Command-Injection-Report.pdf)
- [Exact HTTP requests and results](os-injection-lab/evidence/requests.json)
- [Successful exploit and identical blocked payload](os-injection-lab/evidence/03-comparison-detail.jpg)
- [Google Docs report section](Google-Docs-Report-Section.md)

The required video must contain Manas's own voice-over and show the vulnerable source, exact working payload, root cause, implemented fix, and the same payload failing, in roughly 2-3 minutes. A video is not included until it has actually been recorded.
