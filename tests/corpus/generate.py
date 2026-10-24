#!/usr/bin/env python3
"""Explicitly regenerate the offline corpus; never invoked by cargo test.

Requires Python 3.9+, clang-cl, lld-link, llvm-pdbutil, and optionally MSVC.
Reference counts come from LLVM, never from pdb-sdk. Review all changes.
"""

import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent


def run(command, cwd):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"{command!r}\n{result.stdout}\n{result.stderr}")
    return result.stdout + result.stderr


def version(tool, microsoft=False):
    # link /? may return a nonzero exit code even when it prints valid help.
    result = subprocess.run(
        [tool, "/?" if microsoft else "--version"], cwd=ROOT,
        capture_output=True, text=True, timeout=60,
    )
    text = result.stdout + result.stderr
    if not text.strip() or (result.returncode and not microsoft):
        raise RuntimeError(f"Could not identify tool {tool}: {text}")
    return next(
        (line.strip() for line in text.splitlines() if re.search(r"\bversion\s+\d", line, re.I)),
        text.strip().splitlines()[0],
    )


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference_counts(yaml):
    sections = dict(re.findall(r"^([A-Za-z]+):\n(.*?)(?=^[A-Za-z]+:|\Z)", yaml, re.M | re.S))
    # Only top-level records: nested field-list members must not be counted twice.
    return {
        name: dict(sorted(collections.Counter(
            re.findall(r"^    - Kind:\s+(\w+)", sections[name], re.M)
        ).items()))
        for name in ("TpiStream", "IpiStream")
    }


def generate(pipeline, pdbutil, staging):
    fixture_id, compiler, linker, arch, microsoft_c, microsoft_l = pipeline
    compiler = str(Path(shutil.which(compiler) or compiler).resolve())
    linker = str(Path(shutil.which(linker) or linker).resolve())
    compiler_version = version(compiler, microsoft_c)
    linker_version = version(linker, microsoft_l)
    reference_version = version(pdbutil)
    with tempfile.TemporaryDirectory(prefix="pdb-sdk-corpus-") as work:
        work = Path(work)
        shutil.copyfile(ROOT / "program.c", work / "program.c")
        compile_args = [
            "/nologo", "/c", "/Z7", "/Od", "/GS-", "/Brepro",
            "/Foprogram.obj", "program.c",
        ]
        if not microsoft_c:
            compile_args.insert(0, f"--target={'x86_64' if arch == 'x64' else 'i686'}-pc-windows-msvc")
        link_args = [
            "/nologo", "/nodefaultlib", "/entry:entry", "/subsystem:console",
            "/debug:full", "/incremental:no", "/Brepro", f"/machine:{arch}",
            "/out:program.exe", "/pdb:program.pdb", "program.obj",
        ]
        run([compiler, *compile_args], work)
        run([linker, *link_args], work)
        yaml = run([pdbutil, "pdb2yaml", "--tpi-stream", "--ipi-stream", "program.pdb"], work)
        reference = reference_counts(yaml)
        public_dump = run([pdbutil, "dump", "--publics", "program.pdb"], work)
        public_names = sorted(re.findall(r"S_PUB32[^`\n]*`([^`\n]+)`", public_dump))
        module_dump = run([pdbutil, "dump", "--modules", "program.pdb"], work)
        module_count = len(re.findall(r"^\s*Mod \d+ \|", module_dump, re.M))
        if not public_names or not module_count or not all(reference.values()):
            raise RuntimeError("LLVM reference extraction produced empty expectations")
        destination = staging / f"{fixture_id}.pdb"
        shutil.copyfile(work / "program.pdb", destination)
    return {
        "id": fixture_id,
        "file": destination.name,
        "sha256": sha256(destination),
        "source": "program.c",
        "source_sha256": sha256(ROOT / "program.c"),
        "license": "MIT (repository-owned source)",
        "compiler": compiler_version,
        "linker": linker_version,
        "compile_args": compile_args,
        "link_args": link_args,
        "reference_tool": reference_version,
        "reference_args": [
            "pdb2yaml --tpi-stream --ipi-stream program.pdb",
            "dump --publics program.pdb", "dump --modules program.pdb",
        ],
        "struct_anchor": {
            "name": "Sample",
            "size": 32 if arch == "x64" else 28,
            "members": {"value": 0, "color": 4, "payload": 8, "values": 12, "name": 24},
        },
        "machine": "Amd64" if arch == "x64" else "X86",
        "type_kinds": reference["TpiStream"],
        "id_kinds": reference["IpiStream"],
        "public_names": public_names,
        "module_count": module_count,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default="clang-cl")
    parser.add_argument("--lld", default="lld-link")
    parser.add_argument("--pdbutil", default="llvm-pdbutil")
    parser.add_argument("--cl", help="Path to MSVC cl.exe (requires --link)")
    parser.add_argument("--link", help="Path to Microsoft link.exe (requires --cl)")
    args = parser.parse_args()
    if bool(args.cl) != bool(args.link):
        parser.error("--cl and --link must be supplied together")
    if b"\r" in (ROOT / "program.c").read_bytes():
        parser.error("program.c must use canonical LF line endings (see .gitattributes)")

    pipelines = [
        ("clang-lld-x64", args.clang, args.lld, "x64", False, False),
        ("clang-lld-x86", args.clang, args.lld, "x86", False, False),
    ]
    if args.cl:
        pipelines += [
            ("msvc-link-x64", args.cl, args.link, "x64", True, True),
            ("clang-link-x64", args.clang, args.link, "x64", False, True),
            ("msvc-lld-x64", args.cl, args.lld, "x64", True, False),
        ]

    # Retain other pipelines during an LLVM-only update. Stage every replacement
    # before publishing, so compiler/tool failures cannot leave a half-updated corpus.
    manifest_path = ROOT / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {"schema": 1, "fixtures": []}
    fixtures = {fixture["id"]: fixture for fixture in manifest["fixtures"]}
    with tempfile.TemporaryDirectory(prefix=".staging-", dir=ROOT) as staging:
        staging = Path(staging)
        for pipeline in pipelines:
            fixture = generate(pipeline, args.pdbutil, staging)
            fixtures[fixture["id"]] = fixture
        manifest["fixtures"] = sorted(fixtures.values(), key=lambda fixture: fixture["id"])
        staged_manifest = staging / "manifest.json"
        staged_manifest.write_bytes((json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
        for generated in staging.glob("*.pdb"):
            generated.replace(ROOT / generated.name)
        staged_manifest.replace(manifest_path)


if __name__ == "__main__":
    main()
