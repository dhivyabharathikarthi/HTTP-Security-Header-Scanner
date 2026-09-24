"""CLI runner for the HTTP Security Header Scanner."""

import json
import sys
from app.scanner import perform_scan, ScannerError
from app.database import get_db, init_db

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python -m app.cli <URL>"}))
        sys.exit(1)

    url = sys.argv[1]
    init_db()
    db_gen = get_db()
    db = next(db_gen)

    try:
        result = perform_scan(url, db=db)
        print(result.model_dump_json())
    except (ValueError, ScannerError) as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(2)
    except Exception as exc:
        print(json.dumps({"error": f"Unexpected scan failure: {str(exc)}"}))
        sys.exit(3)
    finally:
        try:
            next(db_gen)
        except StopIteration:
            pass

if __name__ == "__main__":
    main()
