import os
import json, socket
from datetime import datetime
from pprint import pprint
from datetime import datetime, UTC

from src.scan import scan_entry

INPUT_FILE = "scan.list.json"
OUTPUT_FILE = "results/output.{date}.{time}.json"


def main():
    DATABASE = json.load(open(INPUT_FILE, "r"))
    output = {
        "scan_started_utc": datetime.now(UTC).isoformat(),
        "results": [],
    }

    for entry in DATABASE:
        output["results"].append(scan_entry(entry))

    output["scan_finished_utc"] = datetime.now(UTC).isoformat()

    output_path = OUTPUT_FILE.format_map(
        dict(
            date=datetime.now().strftime("%d-%m-%Y"),
            time=datetime.now().strftime("%H:%M:%S"),
            hostname=socket.gethostname(),
        )
    )

    parent_dir = os.path.dirname(output_path) or "."

    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)
    elif not os.path.isdir(parent_dir):
        raise RuntimeError(f"Output path parent exists but is not a directory: {parent_dir}")

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)



    print(f"[+] Scan completed. Raw data written to {output_path}")

    pprint(output)

if __name__ == "__main__":
    main()