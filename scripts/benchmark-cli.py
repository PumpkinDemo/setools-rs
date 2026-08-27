#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

"""Measure end-to-end setools-rs CLI wall time and peak resident memory."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Sequence


TOOLS = {
    "sesearch",
    "seinfo",
    "sediff",
    "sedta",
    "seinfoflow",
    "sechecker",
}


class BenchmarkError(Exception):
    """The benchmark configuration or one of its commands is invalid."""


@dataclass(frozen=True)
class Scenario:
    identifier: str
    description: str
    tool: str
    arguments: tuple[str, ...]
    enabled_by_default: bool
    warmup_runs: int
    measured_runs: int


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def nonnegative_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return parsed


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=repository / "benchmarks/cli-v1.toml",
        help="scenario manifest (default: benchmarks/cli-v1.toml)",
    )
    parser.add_argument("--policy", type=Path, help="binary policy to benchmark")
    parser.add_argument(
        "--tool-dir",
        type=Path,
        default=repository / "target/release",
        help="directory containing the command binaries",
    )
    parser.add_argument(
        "--implementation",
        default="setools-rs",
        help="implementation label recorded in JSON",
    )
    parser.add_argument(
        "--warmups",
        type=nonnegative_integer,
        help="override every scenario's warm-up count",
    )
    parser.add_argument(
        "--runs",
        type=positive_integer,
        help="override every scenario's measured-run count",
    )
    parser.add_argument("--output", type=Path, help="also write JSON to this path")
    parser.add_argument("--list", action="store_true", help="list scenario IDs and exit")
    parser.add_argument("scenario", nargs="*", help="scenario IDs to run (default: all)")
    return parser.parse_args(argv)


def manifest_integer(item: dict[str, object], key: str, minimum: int) -> int:
    value = item.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise BenchmarkError(f"scenario {key} must be an integer >= {minimum}")
    return value


def load_manifest(path: Path) -> tuple[str, list[Scenario]]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise BenchmarkError(f"unable to read {path}: {error}") from error
    if data.get("schema_version") != 1:
        raise BenchmarkError("benchmark manifest schema_version must be 1")
    suite = data.get("suite")
    if not isinstance(suite, str) or not suite:
        raise BenchmarkError("benchmark manifest suite must be a non-empty string")
    raw_scenarios = data.get("scenario")
    if not isinstance(raw_scenarios, list) or not raw_scenarios:
        raise BenchmarkError("benchmark manifest must contain scenarios")

    scenarios: list[Scenario] = []
    identifiers: set[str] = set()
    for raw in raw_scenarios:
        if not isinstance(raw, dict):
            raise BenchmarkError("each benchmark scenario must be a table")
        identifier = raw.get("id")
        description = raw.get("description")
        tool = raw.get("tool")
        arguments = raw.get("args")
        if not isinstance(identifier, str) or not identifier:
            raise BenchmarkError("scenario id must be a non-empty string")
        if identifier in identifiers:
            raise BenchmarkError(f"duplicate scenario id {identifier!r}")
        if not isinstance(description, str) or not description:
            raise BenchmarkError(f"scenario {identifier!r} has no description")
        if tool not in TOOLS:
            raise BenchmarkError(f"scenario {identifier!r} has unknown tool {tool!r}")
        if not isinstance(arguments, list) or not all(
            isinstance(argument, str) for argument in arguments
        ):
            raise BenchmarkError(f"scenario {identifier!r} args must be strings")
        if not any("{policy}" in argument for argument in arguments):
            raise BenchmarkError(f"scenario {identifier!r} does not use {{policy}}")
        unexpected = [
            argument
            for argument in arguments
            if "{" in argument.replace("{policy}", "")
            or "}" in argument.replace("{policy}", "")
        ]
        if unexpected:
            raise BenchmarkError(
                f"scenario {identifier!r} contains an unknown placeholder"
            )
        enabled_by_default = raw.get("default", True)
        if not isinstance(enabled_by_default, bool):
            raise BenchmarkError(
                f"scenario {identifier!r} default must be a Boolean"
            )
        identifiers.add(identifier)
        scenarios.append(
            Scenario(
                identifier=identifier,
                description=description,
                tool=tool,
                arguments=tuple(arguments),
                enabled_by_default=enabled_by_default,
                warmup_runs=manifest_integer(raw, "warmup_runs", 0),
                measured_runs=manifest_integer(raw, "measured_runs", 1),
            )
        )
    return suite, scenarios


def selected_scenarios(
    scenarios: list[Scenario], requested: Sequence[str]
) -> list[Scenario]:
    if not requested:
        return [scenario for scenario in scenarios if scenario.enabled_by_default]
    by_id = {scenario.identifier: scenario for scenario in scenarios}
    unknown = sorted(set(requested).difference(by_id))
    if unknown:
        raise BenchmarkError(f"unknown scenario(s): {', '.join(unknown)}")
    if len(set(requested)) != len(requested):
        raise BenchmarkError("scenario IDs must not be repeated")
    return [by_id[identifier] for identifier in requested]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def cpu_model() -> str | None:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip() in {"model name", "Hardware"}:
                return value.strip()
    except OSError:
        pass
    return None


def command_for(scenario: Scenario, tool_dir: Path, policy: Path) -> list[str]:
    executable = tool_dir / scenario.tool
    arguments = [argument.replace("{policy}", os.fspath(policy)) for argument in scenario.arguments]
    return [os.fspath(executable), *arguments]


def display_command(scenario: Scenario) -> list[str]:
    return [scenario.tool, *scenario.arguments]


def run_once(command: Sequence[str]) -> dict[str, int | float]:
    with tempfile.TemporaryFile() as error_output:
        started = time.perf_counter_ns()
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=error_output,
        )
        try:
            while True:
                try:
                    _, status, usage = os.wait4(process.pid, 0)
                    break
                except InterruptedError:
                    continue
        except BaseException:
            process.kill()
            process.wait()
            raise
        elapsed_ns = time.perf_counter_ns() - started
        process.returncode = os.waitstatus_to_exitcode(status)
        if process.returncode != 0:
            error_output.seek(0)
            diagnostic = error_output.read(8192).decode("utf-8", errors="replace")
            raise BenchmarkError(
                f"command exited {process.returncode}: {command!r}\n{diagnostic.rstrip()}"
            )
    return {
        "wall_time_seconds": round(elapsed_ns / 1_000_000_000, 9),
        "peak_rss_kib": int(usage.ru_maxrss),
    }


def summarize(values: Sequence[int | float], digits: int | None = None) -> dict[str, int | float]:
    summary: dict[str, int | float] = {
        "min": min(values),
        "median": statistics.median(values),
        "max": max(values),
    }
    if digits is not None:
        return {key: round(float(value), digits) for key, value in summary.items()}
    return summary


def tool_inventory(tool_dir: Path, scenarios: Sequence[Scenario]) -> dict[str, object]:
    inventory: dict[str, object] = {}
    for tool in sorted({scenario.tool for scenario in scenarios}):
        executable = tool_dir / tool
        if not executable.is_file():
            raise BenchmarkError(f"missing benchmark executable {executable}")
        if not os.access(executable, os.X_OK):
            raise BenchmarkError(f"benchmark executable is not executable: {executable}")
        version = subprocess.run(
            [executable, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        if version.returncode != 0:
            diagnostic = version.stderr.strip() or version.stdout.strip()
            raise BenchmarkError(
                f"unable to identify benchmark executable {executable}: {diagnostic}"
            )
        inventory[tool] = {
            "version": version.stdout.strip(),
            "sha256": sha256(executable),
        }
    return inventory


def run_suite(
    suite: str,
    scenarios: Sequence[Scenario],
    policy: Path,
    tool_dir: Path,
    implementation: str,
    warmups_override: int | None,
    runs_override: int | None,
) -> dict[str, object]:
    repository = Path(__file__).resolve().parents[1]
    policy = policy.resolve()
    tool_dir = tool_dir.resolve()
    if not policy.is_file():
        raise BenchmarkError(f"policy is not a regular file: {policy}")
    if sys.platform != "linux" or not hasattr(os, "wait4"):
        raise BenchmarkError("peak-RSS measurement currently requires Linux wait4(2)")

    try:
        tool_directory = os.fspath(tool_dir.relative_to(repository))
    except ValueError:
        tool_directory = os.fspath(tool_dir)
    tools = tool_inventory(tool_dir, scenarios)
    results = []
    for scenario in scenarios:
        warmup_runs = (
            scenario.warmup_runs if warmups_override is None else warmups_override
        )
        measured_runs = (
            scenario.measured_runs if runs_override is None else runs_override
        )
        command = command_for(scenario, tool_dir, policy)
        for _ in range(warmup_runs):
            run_once(command)
        samples = [run_once(command) for _ in range(measured_runs)]
        wall_times = [sample["wall_time_seconds"] for sample in samples]
        peak_rss = [sample["peak_rss_kib"] for sample in samples]
        results.append(
            {
                "id": scenario.identifier,
                "description": scenario.description,
                "command": display_command(scenario),
                "warmup_runs": warmup_runs,
                "measured_runs": measured_runs,
                "samples": samples,
                "wall_time_seconds": summarize(wall_times, digits=9),
                "peak_rss_kib": summarize(peak_rss),
            }
        )

    return {
        "schema_version": 1,
        "suite": suite,
        "generated_at_utc": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "implementation": {
            "name": implementation,
            "tool_directory": tool_directory,
            "tools": tools,
        },
        "policy": {
            "name": policy.name,
            "size_bytes": policy.stat().st_size,
            "sha256": sha256(policy),
        },
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_model": cpu_model(),
            "logical_cpus": os.cpu_count(),
            "python": platform.python_version(),
        },
        "measurement": {
            "wall_clock": "time.perf_counter_ns",
            "peak_rss": "wait4(2) ru_maxrss in KiB",
            "stdout": "discarded",
            "stderr": "discarded after successful runs",
            "cache_state": "warm-up counts are defined per scenario in the manifest",
        },
        "scenarios": results,
    }


def encode_json(result: object) -> str:
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def main(argv: Sequence[str] = sys.argv[1:]) -> int:
    arguments = parse_args(argv)
    try:
        suite, all_scenarios = load_manifest(arguments.manifest)
        if arguments.list:
            for scenario in all_scenarios:
                profile = "default" if scenario.enabled_by_default else "manual"
                print(
                    f"{scenario.identifier}\t{profile}\t{scenario.description}"
                )
            return 0
        scenarios = selected_scenarios(all_scenarios, arguments.scenario)
        if arguments.policy is None:
            raise BenchmarkError("--policy is required unless --list is used")
        result = run_suite(
            suite,
            scenarios,
            arguments.policy,
            arguments.tool_dir,
            arguments.implementation,
            arguments.warmups,
            arguments.runs,
        )
        encoded = encode_json(result)
        if arguments.output is not None:
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
        return 0
    except (BenchmarkError, OSError, ValueError) as error:
        print(f"benchmark-cli: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
