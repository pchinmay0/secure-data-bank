"""Load public sample datasets into the API. Development use only."""

import io
import sys
import urllib.error
import urllib.request

API = "http://localhost:8000"
SOURCE = "https://noaa-ghcn-pds.s3.amazonaws.com/csv/by_station"
MAX_BYTES = 25 * 1024 * 1024

# (station id, dataset name, owner institution, sensitivity, shared with)
SEEDS = [
    ("ASN00008051", "Carnarvon Airport daily climate", "UniversityA", "public", []),
    ("USW00094728", "New York Central Park daily climate", "UniversityA", "internal", ["LabB"]),
    ("USW00023169", "Las Vegas McCarran daily climate", "UniversityA", "restricted", []),
    ("CA001108395", "Vancouver Harbour daily climate", "LabB", "public", []),
    ("UK000056225", "Hadley Centre daily climate", "LabB", "internal", []),
    ("USW00012842", "Tampa International daily climate", "LabB", "restricted", ["UniversityA"]),
]

DESCRIPTION = (
    "Daily observations from NOAA's Global Historical Climatology Network (GHCN-Daily), "
    "station {station}. Source: AWS Open Data, public domain."
)


def fetch(station: str) -> bytes:
    url = f"{SOURCE}/{station}.csv"
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{station}.csv is larger than {MAX_BYTES} bytes")
    return data


def upload(station, name, owner, sensitivity, shared, content: bytes) -> None:
    fields = [
        ("name", name),
        ("description", DESCRIPTION.format(station=station)),
        ("owner_institution", owner),
        ("sensitivity", sensitivity),
        *[("shared_with", s) for s in shared],
    ]
    body, content_type = encode_multipart(fields, f"{station}.csv", content)

    request = urllib.request.Request(
        f"{API}/datasets", data=body, headers={"Content-Type": content_type}
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        print(f"  uploaded as dataset id {response.status}: {name}")


def encode_multipart(fields, filename: str, content: bytes):
    boundary = "----databankseed7f3c1e"
    buffer = io.BytesIO()

    for key, value in fields:
        buffer.write(f"--{boundary}\r\n".encode())
        buffer.write(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode())
        buffer.write(f"{value}\r\n".encode())

    buffer.write(f"--{boundary}\r\n".encode())
    buffer.write(
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    )
    buffer.write(b"Content-Type: text/csv\r\n\r\n")
    buffer.write(content)
    buffer.write(f"\r\n--{boundary}--\r\n".encode())

    return buffer.getvalue(), f"multipart/form-data; boundary={boundary}"


def main() -> int:
    failures = 0
    for station, name, owner, sensitivity, shared in SEEDS:
        print(f"{station}: downloading...")
        try:
            content = fetch(station)
            print(f"  {len(content):,} bytes")
            upload(station, name, owner, sensitivity, shared, content)
        except urllib.error.HTTPError as exc:
            failures += 1
            print(f"  FAILED: HTTP {exc.code} {exc.reason}", file=sys.stderr)
        except Exception as exc:
            failures += 1
            print(f"  FAILED: {exc}", file=sys.stderr)

    print(f"\nDone. {len(SEEDS) - failures} succeeded, {failures} failed.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())