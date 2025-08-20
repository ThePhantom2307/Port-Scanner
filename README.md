
# PortScanner (Python)

  

A simple, fast TCP **port scanner** written in Python. It validates an IPv4 address, spawns a thread per port (1–65535), and reports which ports accepted a TCP connection, alongside a best-guess service name from a static mapping. Optionally, results can be saved to a file.

  

> ⚠️ **Legal & ethical use only.** Only scan hosts you own or are explicitly authorized to test. Port scanning may be illegal or against terms of service in many environments.

  

---

  

## How it works

  

-  **IPv4 validation:** Uses `socket.inet_aton` to verify the target is a valid IPv4 address (hostnames are **not** accepted).

-  **TCP connect scan:** For each port in `1..65535`, the script attempts a TCP connection using `socket.connect_ex`.

-  **Thread-per-port:** Spawns one thread per port to run scans concurrently.

-  **Timeout:** Uses a short socket timeout of `0.1` seconds (100 ms).

-  **Service hints:** Maps common ports to service names via the `port_services` dictionary.

-  **Optional export:** When four CLI arguments are provided, results are also written to the specified filename.

  

---

  

## Requirements

  

- Python 3.x

- No external dependencies; uses only the standard library.

  

Tested on Linux/macOS/Windows with Python 3.8+.

  

---

  

## Usage

  

```

python3 portscanner.py <ip> [-s <filename>]

```

  

**Arguments**

  

-  `<ip>` — Required. Target **IPv4 address** (e.g., `192.168.1.10`).

-  `-s <filename>` — Optional. Save results to a text file.

  

> Note: The current implementation only checks that there are **four** arguments to trigger saving; it does **not** validate that the third token is literally `-s`. For clarity, pass `-s` as shown below.

  

### Examples

  

Scan a host and print results to the terminal:

```bash

python3  portscanner.py  192.168.1.10

```

  

Scan and also save to `results.txt`:

```bash

python3  portscanner.py  192.168.1.10  -s  results.txt

```

  

Quick test against localhost:

```bash

python3  portscanner.py  127.0.0.1

```

  

---

  

## Sample output

  

```

==================================================

Scanning target: 192.168.1.10

Time started: 2025-08-21 10:15:30.123456

==================================================

  

__________________________________________________

  

PORTS SERVICE

__________________________________________________

22 SSH

80 HTTP

443 HTTPS

  

==================================================

Number of open ports: 3

  

Time finished: 2025-08-21 10:15:45.987654

Time duration: 0:00:15.864198

==================================================

```

  

If saving to a file with `-s results.txt`, the file will include a similar table.

  

---

  

## Notes & limitations

  

-  **IPv4 only:** Hostnames and IPv6 are not supported (the script rejects non-IPv4 input).

-  **TCP only:** This is a TCP connect scan. UDP and half-open/SYN scans are not implemented.

-  **Service identification:** Service names are inferred from a static `port_services` map and may not reflect the actual application listening on the port.

-  **Aggressive threading:** Spawning 65k threads can be **resource-intensive** and may:

	- Hit OS thread limits,

	- Cause inaccurate results on slow/remote networks,

	- Trigger IDS/IPS/firewalls.

-  **Short timeout:** The global `socket.setdefaulttimeout(0.1)` (100 ms) favors speed but can increase false negatives on high-latency links. Increase this value for distant hosts.

-  **File output detail:** When four arguments are passed, results are written to the file from the 4th argument. (Minor typo in code: “Unkown Service” in file output.)

  

---

  

## Error handling

  

The script handles:

- Invalid IP formats,

-  `KeyboardInterrupt` (Ctrl+C),

- Unresolvable hostnames (though hostnames are rejected earlier),

- Generic file-write errors when saving.

  

---

  

## Performance tips (optional improvements)

  

If you plan to evolve this script:

  

- Use a **thread pool** (`concurrent.futures.ThreadPoolExecutor`) with a sane `max_workers` (e.g., 200–1000) instead of 65k threads.

- Add **arg parsing** with `argparse` (e.g., set timeout, choose port ranges, toggle output file).

- Support **hostnames/IPv6**, **UDP scanning**, and **banner grabbing** for better service detection.

- Add **rate limiting** and a **progress indicator**.

- Consider **retries** or adaptive timeouts for slow networks.

  

---

  

## Safety & responsibility

  

- Obtain **explicit permission** before scanning.

- Be mindful of **rate limits**, **corporate policies**, and **ISP/hosting ToS**.

- Prefer scanning in controlled lab or test environments first.
