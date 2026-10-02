#!/usr/bin/env python3
"""Record container runtime calls and emulate the launcher queries."""
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["TEST_RUNTIME_LOG"], "a") as out:
    out.write(json.dumps(args) + "\n")

if args[:1] == ["info"] and "--format" in args:
    fmt = args[args.index("--format") + 1]
    if "Runtimes" in fmt:
        print(os.environ.get("TEST_RUNTIMES", "runc\nrunsc"))
    elif "SecurityOptions" in fmt:
        print(os.environ.get("TEST_DOCKER_SECURITY_OPTIONS", "[]"))
    elif "Rootless" in fmt:
        print(os.environ.get("TEST_PODMAN_ROOTLESS", "true"))
elif args[:2] == ["network", "inspect"] and "--format" in args:
    fmt = args[args.index("--format") + 1]
    if "Driver" in fmt:
        print(os.environ.get("TEST_NETWORK_DRIVER", "bridge"))
    elif "Name" in fmt:
        print(os.environ.get("TEST_NETWORK_NAME", args[-1]))
elif args[:2] == ["network", "inspect"]:
    if os.environ.get("TEST_NET_MISSING") == "1":
        sys.exit(1)
sys.exit(0)
