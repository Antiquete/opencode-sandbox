#!/usr/bin/env python3
"""Record container runtime calls and emulate the launcher queries."""
import json
import os
import sys

args = sys.argv[1:]
runtime = os.path.basename(sys.argv[0]).upper()
with open(os.environ["TEST_RUNTIME_LOG"], "a") as out:
    out.write(json.dumps(args) + "\n")

if args[:1] == ["info"] and os.environ.get(f"TEST_{runtime}_INFO_FAIL") == "1":
    sys.exit(1)

if args[:1] == ["info"] and "--format" in args:
    fmt = args[args.index("--format") + 1]
    if "Runtimes" in fmt:
        if "SecurityOptions" in fmt:
            print(os.environ.get("TEST_DOCKER_SECURITY_OPTIONS", "[]"))
            print("runtimes")
        print(os.environ.get("TEST_RUNTIMES", "runc\nrunsc"))
    elif "SecurityOptions" in fmt:
        print(os.environ.get("TEST_DOCKER_SECURITY_OPTIONS", "[]"))
    elif "Rootless" in fmt:
        print(os.environ.get("TEST_PODMAN_ROOTLESS", "true"))
    if os.environ.get(f"TEST_{runtime}_INFO_FORMAT_FAIL") == "1":
        sys.exit(1)
elif args[:2] == ["network", "inspect"] and "--format" in args:
    fmt = args[args.index("--format") + 1]
    if "Driver" in fmt:
        print(os.environ.get("TEST_NETWORK_DRIVER", "bridge"))
    elif "Name" in fmt:
        print(os.environ.get("TEST_NETWORK_NAME", args[-1]))
elif args[:2] == ["network", "inspect"]:
    if os.environ.get("TEST_NET_MISSING") == "1":
        sys.exit(1)
if args[:1] == ["run"] and os.environ.get(f"TEST_{runtime}_RUN_FAIL") == "1":
    sys.exit(1)
sys.exit(0)
