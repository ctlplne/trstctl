# SPDX-License-Identifier: BUSL-1.1
"""A narrow executable contract for our SPL files, not a Splunk emulator.

Only the commands below are interpreted. Any unsupported syntax fails closed.
The real search engine, scheduler, RBAC and alert actions need a vendor run.
"""

import configparser
import math
from pathlib import Path
import re
import shlex

ASSETS = {
    "default/app.conf",
    "default/props.conf",
    "default/macros.conf",
    "default/savedsearches.conf",
    "metadata/default.meta",
    "README.md",
    "LICENSE",
    "default/data/ui/nav/default.xml",
    "default/data/ui/views/overview.xml",
}


def read_conf(path):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    with path.open(encoding="utf-8") as handle:
        parser.read_string(re.sub(r"(?m)^\[\]$", "[__app__]", handle.read()))
    return {name: dict(parser[name]) for name in parser.sections()}


def field(row, name):
    value = row
    for part in name.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def compile_query(query):
    commands = [part.strip() for part in query.split("|")]
    base = re.fullmatch(
        r'`trstctl_scope` sourcetype="trstctl:audit" type="([a-z_.]+)"', commands[0]
    )
    if base is None:
        raise ValueError(
            "unsupported base search: explicit scope/audit sourcetype/type required"
        )
    instructions = [("base", base.group(1))]
    for command in commands[1:]:
        match = re.fullmatch(r"spath path=(data\.[a-z_]+) output=([a-z_]+)", command)
        if match:
            instructions.append(("spath", match.groups()))
            continue
        if command.startswith("search "):
            terms = shlex.split(command[7:])
            if not terms or any(
                re.fullmatch(r"[a-z_][a-z_.]*=\*", term) is None for term in terms
            ):
                raise ValueError("unsupported search filter")
            instructions.append(("present", [term[:-2] for term in terms]))
            continue
        match = re.fullmatch(r"dedup ([a-z_]+(?: [a-z_]+)*)", command)
        if match:
            instructions.append(("dedup", match.group(1).split()))
            continue
        match = re.fullmatch(
            r"stats count AS event_count values\(id\) AS event_ids BY ([a-z_]+(?: [a-z_]+)*)",
            command,
        )
        if match:
            instructions.append(("stats", match.group(1).split()))
            continue
        match = re.fullmatch(r"where event_count>=(\d+)", command)
        if match:
            instructions.append(("threshold", int(match.group(1))))
            continue
        raise ValueError("unsupported SPL command: " + command)
    kinds = [kind for kind, _ in instructions]
    if kinds not in (
        ["base", "present", "dedup", "stats", "threshold"],
        ["base", "spath", "present", "dedup", "stats", "threshold"],
    ):
        raise ValueError("unsupported command order")
    if next(value for kind, value in instructions if kind == "dedup") != [
        "tenant_id",
        "id",
    ]:
        raise ValueError("unsupported dedup: tenant and stable event ID required")
    return instructions


class App:
    def __init__(self, root):
        self.root = Path(root)
        self.searches = read_conf(self.root / "default/savedsearches.conf")

    def validate(self):
        found = set()
        for path in self.root.rglob("*"):
            if path.is_symlink():
                raise ValueError("app contains a symlink")
            if path.is_file():
                found.add(path.relative_to(self.root).as_posix())
                if path.stat().st_size > 1 << 20:
                    raise ValueError("app asset exceeds bound")
        if found != ASSETS:
            raise ValueError(f"unexpected/missing app assets: {found ^ ASSETS}")
        config = read_conf(self.root / "default/app.conf")
        if (
            re.fullmatch(r"[1-9][0-9]*", config.get("install", {}).get("build", ""))
            is None
        ):
            raise ValueError("a positive app build identifier is required")
        if (
            config["install"].get("is_configured") != "true"
            or config.get("ui", {}).get("check_for_updates") != "false"
        ):
            raise ValueError(
                "manual setup must not advertise a custom wizard or enable update callouts"
            )
        if "setup_view" in config["ui"]:
            raise ValueError("this app has no custom setup view")
        macros = read_conf(self.root / "default/macros.conf")
        if macros != {
            "trstctl_scope": {
                "definition": 'index="__trstctl_configure_index__" tenant_id="__trstctl_configure_tenant__"',
                "iseval": "0",
            }
        }:
            raise ValueError("packaged scope must retain deny-all placeholders")
        for search in self.searches.values():
            for key, expected in {
                "disabled": "true",
                "enableSched": "0",
                "actions": "",
                "dispatch.earliest_time": "-15m",
                "dispatch.latest_time": "now",
                "cron_schedule": "*/5 * * * *",
            }.items():
                if search.get(key) != expected:
                    raise ValueError("unsafe search default: " + key)
            instructions = compile_query(search["search"])
            if search.get("alert_condition") != "search event_count>=" + str(
                instructions[-1][1]
            ):
                raise ValueError("alert condition differs from the result threshold")
            if any(
                key in search
                for key in ("alert_type", "alert_comparator", "alert_threshold")
            ):
                raise ValueError("use documented savedsearches.conf alert_condition")
        props = read_conf(self.root / "default/props.conf")
        if props.get("trstctl:audit", {}).get("KV_MODE") != "json":
            raise ValueError("audit JSON extraction is absent")
        metadata = read_conf(self.root / "metadata/default.meta")
        if any(
            value.get("export") != "none"
            or value.get("access") != "read : [ admin ], write : [ admin ]"
            for value in metadata.values()
        ):
            raise ValueError("packaged objects must remain app-local and admin-only")

    def evaluate(self, name, events, index, tenant, now):
        """Evaluate default query text ad hoc; no scheduler or saved-search enablement is modeled."""
        instructions = compile_query(self.searches[name]["search"])
        if not math.isfinite(now):
            raise ValueError("invalid search time")
        if (
            not isinstance(index, str)
            or not isinstance(tenant, str)
            or not re.fullmatch(r"[A-Za-z0-9_]+", index)
            or not re.fullmatch(r"[A-Za-z0-9_-]+", tenant)
        ):
            raise ValueError("invalid explicit scaffold index/tenant scope")
        if index.startswith("__trstctl_") or tenant.startswith("__trstctl_"):
            return []
        event_type = instructions[0][1]
        rows = []
        for item in events:
            event = item.get("event")
            timestamp = item.get("_time")
            if (
                not isinstance(event, dict)
                or isinstance(timestamp, bool)
                or not isinstance(timestamp, (int, float))
                or not math.isfinite(timestamp)
            ):
                continue
            if (
                item.get("index") == index
                and item.get("sourcetype") == "trstctl:audit"
                and event.get("tenant_id") == tenant
                and event.get("type") == event_type
                and now - 900 <= timestamp < now
            ):
                rows.append(dict(event, _time=timestamp))
        rows.sort(key=lambda row: row["_time"], reverse=True)
        for kind, value in instructions[1:]:
            if kind == "spath":
                source, destination = value
                for row in rows:
                    row[destination] = field(row, source)
            elif kind == "present":
                rows = [
                    row
                    for row in rows
                    if all(
                        isinstance(field(row, key), str) and field(row, key) != ""
                        for key in value
                    )
                ]
            elif kind == "dedup":
                seen, unique = set(), []
                for row in rows:
                    key = tuple(field(row, key) for key in value)
                    if key not in seen:
                        seen.add(key)
                        unique.append(row)
                rows = unique
            elif kind == "stats":
                groups = {}
                for row in rows:
                    key = tuple(field(row, key) for key in value)
                    if any(part in (None, "") for part in key):
                        continue
                    aggregate = groups.setdefault(
                        key, dict(zip(value, key), event_count=0, event_ids=[])
                    )
                    aggregate["event_count"] += 1
                    aggregate["event_ids"].append(row["id"])
                rows = list(groups.values())
                for row in rows:
                    row["event_ids"] = sorted(set(row["event_ids"]))
            elif kind == "threshold":
                rows = [row for row in rows if row["event_count"] >= value]
            else:
                raise ValueError("unsupported compiled command")
        return sorted(rows, key=lambda row: tuple(str(row[key]) for key in sorted(row)))
