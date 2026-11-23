from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from stat import S_ISDIR, S_ISREG
from typing import Final, TypedDict

from .codebert_input import sha256_file


@dataclass(frozen=True, slots=True)
class PackageLayout:
    directories: tuple[str, ...]
    files: tuple[str, ...]


ORIGINAL: Final = PackageLayout(("cases",), ("manifest.json",))
INTAKE: Final = PackageLayout(
    ("runtime_cases", "synthetic_cases"),
    ("label_manifest.jsonl", "training_split_manifest.jsonl",
     "labeling_guideline.md", "training_data_contract.json"),
)


class FileEntry(TypedDict):
    path: str
    bytes: int
    sha256: str


class InventoryIssue(TypedDict):
    path: str
    reason: str


class PackageInventory(TypedDict):
    files: list[FileEntry]
    issues: list[InventoryIssue]


@dataclass(frozen=True, slots=True)
class PackageIntegrityError(ValueError):
    path: str
    reason: str

    def __str__(self) -> str:
        return f"{self.path}: {self.reason}"


def inventory_package(root: Path, layout: PackageLayout) -> PackageInventory:
    directories: set[str] = set()
    files: list[FileEntry] = []
    issues: list[InventoryIssue] = []
    pending = [root]
    while pending:
        path = pending.pop()
        relative = path.relative_to(root).as_posix()
        try:
            info = path.lstat()
            if S_ISDIR(info.st_mode):
                pending.extend(path.iterdir())
                directories.add(relative)
            elif path != root and S_ISREG(info.st_mode):
                files.append({"path": relative, "bytes": info.st_size, "sha256": sha256_file(path)})
            else:
                issues.append({"path": relative, "reason": "unsupported_entry"})
        except FileNotFoundError:
            issues.append({"path": relative, "reason": "missing"})
        except OSError:
            issues.append({"path": relative, "reason": "unreadable"})

    file_names = {entry["path"] for entry in files}
    failed_paths = {issue["path"] for issue in issues}
    for required in layout.files:
        if required not in file_names and required not in failed_paths:
            issues.append({"path": required, "reason": "required_file_missing"})
    for required in layout.directories:
        if required in failed_paths:
            continue
        if required not in directories:
            issues.append({"path": required, "reason": "required_directory_missing"})
        elif not any(name.startswith(f"{required}/") for name in file_names):
            issues.append({"path": required, "reason": "required_directory_empty"})

    return {
        "files": sorted(files, key=lambda entry: entry["path"]),
        "issues": sorted(issues, key=lambda issue: (issue["path"], issue["reason"])),
    }


def verified_paths(root: Path, layout: PackageLayout) -> frozenset[str]:
    inventory = inventory_package(root, layout)
    if inventory["issues"]:
        issue = inventory["issues"][0]
        raise PackageIntegrityError(issue["path"], issue["reason"])
    sums_name = "SHA256SUMS.txt"
    files = {entry["path"]: entry["sha256"] for entry in inventory["files"]}
    if sums_name not in files:
        raise PackageIntegrityError(sums_name, "missing checksum list")
    del files[sums_name]
    expected: dict[str, str] = {}
    try:
        lines = (root / sums_name).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise PackageIntegrityError(sums_name, "unreadable checksum list") from exc
    for number, line in enumerate(lines, start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise PackageIntegrityError(sums_name, f"invalid checksum entry on line {number}")
        digest, spelling = match.groups()
        path = PurePosixPath(spelling)
        name = path.as_posix()
        if path.is_absolute() or ".." in path.parts or "\\" in spelling or name in expected:
            raise PackageIntegrityError(sums_name, f"invalid or duplicate path on line {number}")
        expected[name] = digest
    difference = files.keys() ^ expected.keys()
    if difference:
        raise PackageIntegrityError(min(difference), "file inventory differs from checksum list")
    for name, digest in expected.items():
        if files[name] != digest:
            raise PackageIntegrityError(name, "SHA-256 mismatch")
    return frozenset(expected)


def main() -> int:
    parser = argparse.ArgumentParser(description="List case intake files and compute their SHA-256 digests.")
    parser.add_argument("--original", type=Path, required=True, help="original case package root")
    parser.add_argument("--intake", type=Path, required=True, help="framework intake package root")
    args = parser.parse_args()
    original = inventory_package(args.original, ORIGINAL)
    intake = inventory_package(args.intake, INTAKE)
    print(json.dumps({"original": original, "intake": intake}, ensure_ascii=True, indent=2))
    return 1 if original["issues"] or intake["issues"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
