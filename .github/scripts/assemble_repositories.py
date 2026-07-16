#!/usr/bin/env python3
"""Assemble Clavenar sibling repositories from Cargo and Compose manifests.

The checkout layout is part of the build contract: Clavenar Cargo manifests
use sibling path dependencies and Compose files use sibling build and named
contexts. This tool derives that layout from the manifests themselves, clones
missing repositories, and rejects ambiguous existing destinations.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
REPOSITORY_NAME = re.compile(r"^clavenar-[a-z0-9]+(?:-[a-z0-9]+)*$")
RUST_LITERAL_INCLUDE = re.compile(
    r'include_(?:str|bytes)!\(\s*"([^"\\]+)"\s*\)', re.MULTILINE
)
NON_FILESYSTEM_CONTEXT_PREFIXES = (
    "docker-image://",
    "git://",
    "http://",
    "https://",
    "oci-layout://",
    "service:",
    "target:",
)


class AssemblyError(RuntimeError):
    """A fail-closed assembly contract violation."""


@dataclass
class Requirement:
    name: str
    destination: Path
    reasons: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class RepositoryState:
    head: str
    origin: str


def _run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=dict(env) if env is not None else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise AssemblyError(f"command failed ({' '.join(command)}): {detail}")
    return result


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _relative_to(path: Path, parent: Path) -> Path | None:
    try:
        return path.relative_to(parent)
    except ValueError:
        return None


def repository_destination(
    referenced_path: Path,
    *,
    source_root: Path,
    workspace_parent: Path,
) -> Path | None:
    """Map an external manifest path to its exact sibling repository root."""

    referenced_path = _resolved(referenced_path)
    source_root = _resolved(source_root)
    workspace_parent = _resolved(workspace_parent)
    if _relative_to(referenced_path, source_root) is not None:
        return None
    relative = _relative_to(referenced_path, workspace_parent)
    if relative is None or not relative.parts:
        raise AssemblyError(
            f"manifest path escapes assembly workspace {workspace_parent}: "
            f"{referenced_path}"
        )
    name = relative.parts[0]
    if not REPOSITORY_NAME.fullmatch(name):
        raise AssemblyError(
            f"external manifest path must name an exact clavenar-* sibling: "
            f"{referenced_path}"
        )
    return workspace_parent / name


def _add_requirement(
    requirements: dict[Path, Requirement], destination: Path, reason: str
) -> None:
    destination = _resolved(destination)
    requirement = requirements.setdefault(
        destination,
        Requirement(name=destination.name, destination=destination),
    )
    requirement.reasons.add(reason)


def _iter_cargo_path_entries(
    value: Any, breadcrumbs: tuple[str, ...] = ()
) -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        path = value.get("path")
        if isinstance(path, str):
            label = ".".join(breadcrumbs) or "path"
            yield label, path
        for key, child in value.items():
            yield from _iter_cargo_path_entries(child, (*breadcrumbs, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_cargo_path_entries(child, (*breadcrumbs, str(index)))


def _cargo_manifests(repository_root: Path) -> list[Path]:
    ignored = {".git", "target", ".venv", "node_modules"}
    manifests = [
        path
        for path in repository_root.rglob("Cargo.toml")
        if not any(part in ignored for part in path.relative_to(repository_root).parts)
    ]
    return sorted(manifests, key=lambda path: path.as_posix())


def discover_cargo_requirements(
    repository_root: Path, workspace_parent: Path
) -> dict[Path, Requirement]:
    repository_root = _resolved(repository_root)
    requirements: dict[Path, Requirement] = {}
    for manifest in _cargo_manifests(repository_root):
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise AssemblyError(f"cannot parse Cargo manifest {manifest}: {error}") from error
        relative_manifest = manifest.relative_to(repository_root).as_posix()
        for label, dependency_path in _iter_cargo_path_entries(document):
            referenced = manifest.parent / dependency_path
            destination = repository_destination(
                referenced,
                source_root=repository_root,
                workspace_parent=workspace_parent,
            )
            if destination is not None:
                _add_requirement(
                    requirements,
                    destination,
                    f"cargo:{repository_root.name}/{relative_manifest}:{label}",
                )
    return requirements


def discover_rust_include_requirements(
    repository_root: Path, workspace_parent: Path
) -> dict[Path, Requirement]:
    """Discover literal include_str!/include_bytes! sibling inputs."""

    repository_root = _resolved(repository_root)
    requirements: dict[Path, Requirement] = {}
    ignored = {".git", "target", ".venv", "node_modules"}
    sources = [
        path
        for path in repository_root.rglob("*.rs")
        if not any(part in ignored for part in path.relative_to(repository_root).parts)
    ]
    for source in sorted(sources, key=lambda path: path.as_posix()):
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as error:
            raise AssemblyError(f"cannot read Rust source {source}: {error}") from error
        relative_source = source.relative_to(repository_root).as_posix()
        for match in RUST_LITERAL_INCLUDE.finditer(text):
            referenced = source.parent / match.group(1)
            destination = repository_destination(
                referenced,
                source_root=repository_root,
                workspace_parent=workspace_parent,
            )
            if destination is not None:
                _add_requirement(
                    requirements,
                    destination,
                    f"rust-include:{repository_root.name}/{relative_source}",
                )
    return requirements


def _filesystem_context_path(value: str, compose_file: Path) -> Path | None:
    if value.startswith(NON_FILESYSTEM_CONTEXT_PREFIXES):
        return None
    path = Path(value)
    if not path.is_absolute():
        path = compose_file.parent / path
    return path


def compose_requirements_from_model(
    model: Mapping[str, Any],
    *,
    compose_file: Path,
    repository_root: Path,
    workspace_parent: Path,
) -> dict[Path, Requirement]:
    requirements: dict[Path, Requirement] = {}
    services = model.get("services", {})
    if not isinstance(services, dict):
        raise AssemblyError(f"Compose model has no services object: {compose_file}")
    try:
        compose_label = compose_file.relative_to(repository_root).as_posix()
    except ValueError:
        compose_label = compose_file.as_posix()
    for service_name in sorted(services):
        service = services[service_name]
        if not isinstance(service, dict):
            continue
        build = service.get("build")
        if isinstance(build, str):
            build = {"context": build}
        if not isinstance(build, dict):
            continue
        contexts: list[tuple[str, str]] = []
        context = build.get("context")
        if isinstance(context, str):
            contexts.append(("context", context))
        additional = build.get("additional_contexts", {})
        if isinstance(additional, dict):
            contexts.extend(
                (f"additional_context:{name}", value)
                for name, value in sorted(additional.items())
                if isinstance(value, str)
            )
        elif isinstance(additional, list):
            for entry in additional:
                if isinstance(entry, str) and "=" in entry:
                    name, value = entry.split("=", 1)
                    contexts.append((f"additional_context:{name}", value))
        for kind, value in contexts:
            referenced = _filesystem_context_path(value, compose_file)
            if referenced is None:
                continue
            destination = repository_destination(
                referenced,
                source_root=repository_root,
                workspace_parent=workspace_parent,
            )
            if destination is not None:
                _add_requirement(
                    requirements,
                    destination,
                    f"compose:{compose_label}:{service_name}:{kind}",
                )
    return requirements


def render_compose_model(
    compose_files: Sequence[Path], profiles: Sequence[str], repository_root: Path
) -> Mapping[str, Any]:
    command = ["docker", "compose"]
    for compose_file in compose_files:
        command.extend(("-f", str(compose_file)))
    for profile in profiles:
        command.extend(("--profile", profile))
    command.extend(("config", "--format", "json"))
    result = _run(command, cwd=repository_root)
    try:
        model = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AssemblyError(f"docker compose returned invalid JSON: {error}") from error
    if not isinstance(model, dict):
        raise AssemblyError("docker compose model must be a JSON object")
    return model


def discover_compose_requirements(
    compose_files: Sequence[Path],
    profiles: Sequence[str],
    repository_root: Path,
    workspace_parent: Path,
) -> dict[Path, Requirement]:
    if not compose_files:
        return {}
    model = render_compose_model(compose_files, profiles, repository_root)
    requirements: dict[Path, Requirement] = {}
    # Compose merges all -f inputs into one model. The first file is the base
    # manifest and provides the stable receipt label for the resolved graph.
    receipt_file = compose_files[0]
    discovered = compose_requirements_from_model(
        model,
        compose_file=receipt_file,
        repository_root=repository_root,
        workspace_parent=workspace_parent,
    )
    for requirement in discovered.values():
        for reason in requirement.reasons:
            _add_requirement(requirements, requirement.destination, reason)
    return requirements


def _merge_requirements(
    target: dict[Path, Requirement], source: Mapping[Path, Requirement]
) -> None:
    for requirement in source.values():
        for reason in requirement.reasons:
            _add_requirement(target, requirement.destination, reason)


def _requires_recursive_scan(requirement: Requirement) -> bool:
    return any(
        reason.startswith("cargo:") or reason.endswith(":context")
        for reason in requirement.reasons
    )


def discover_graph(
    root: Path,
    workspace_parent: Path,
    compose_files: Sequence[Path],
    profiles: Sequence[str],
) -> dict[Path, Requirement]:
    root = _resolved(root)
    workspace_parent = _resolved(workspace_parent)
    requirements = discover_compose_requirements(
        compose_files, profiles, root, workspace_parent
    )
    scan_queue = [root]
    scanned: set[Path] = set()
    while scan_queue:
        repository = scan_queue.pop(0)
        repository = _resolved(repository)
        if repository in scanned:
            continue
        scanned.add(repository)
        _merge_requirements(
            requirements,
            discover_cargo_requirements(repository, workspace_parent),
        )
        _merge_requirements(
            requirements,
            discover_rust_include_requirements(repository, workspace_parent),
        )
        for requirement in sorted(
            requirements.values(), key=lambda item: item.destination.as_posix()
        ):
            if (
                _requires_recursive_scan(requirement)
                and requirement.destination.is_dir()
                and requirement.destination not in scanned
            ):
                scan_queue.append(requirement.destination)
    return requirements


def _normalize_origin(origin: str) -> str:
    origin = origin.strip()
    if origin.startswith("git@github.com:"):
        origin = "https://github.com/" + origin.removeprefix("git@github.com:")
    elif origin.startswith("ssh://git@github.com/"):
        origin = "https://github.com/" + origin.removeprefix(
            "ssh://git@github.com/"
        )
    return origin.removesuffix("/").removesuffix(".git").lower()


def validate_repository(
    destination: Path, *, name: str, owner: str, ref: str
) -> RepositoryState:
    destination = _resolved(destination)
    if destination.is_symlink():
        raise AssemblyError(f"repository destination must not be a symlink: {destination}")
    if not destination.is_dir():
        raise AssemblyError(f"repository destination is not a directory: {destination}")
    top = _resolved(
        Path(_run(("git", "-C", str(destination), "rev-parse", "--show-toplevel")).stdout.strip())
    )
    if top != destination:
        raise AssemblyError(
            f"destination is not an exact repository root: {destination} (top {top})"
        )
    origin = _run(
        ("git", "-C", str(destination), "remote", "get-url", "origin")
    ).stdout.strip()
    expected_origin = f"https://github.com/{owner}/{name}"
    if _normalize_origin(origin) != expected_origin.lower():
        raise AssemblyError(
            f"wrong origin for {name}: expected {expected_origin}, found {origin}"
        )
    dirty = _run(
        ("git", "-C", str(destination), "status", "--porcelain=v1")
    ).stdout
    if dirty:
        raise AssemblyError(f"repository destination is dirty: {destination}")
    head = _run(("git", "-C", str(destination), "rev-parse", "HEAD")).stdout.strip()
    ref_candidates = [ref]
    if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
        ref_candidates = [f"refs/remotes/origin/{ref}", f"refs/heads/{ref}", ref]
    expected_head = None
    for candidate in ref_candidates:
        result = subprocess.run(
            ("git", "-C", str(destination), "rev-parse", f"{candidate}^{{commit}}"),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 0:
            expected_head = result.stdout.strip()
            break
    if expected_head is None:
        raise AssemblyError(f"cannot resolve required ref {ref!r} in {destination}")
    if head != expected_head:
        raise AssemblyError(
            f"wrong HEAD for {name}: required {ref} ({expected_head}), found {head}"
        )
    return RepositoryState(head=head, origin=origin)


def clone_repository(
    destination: Path, *, name: str, owner: str, ref: str, environment: Mapping[str, str]
) -> RepositoryState:
    destination = _resolved(destination)
    if destination.exists() or destination.is_symlink():
        raise AssemblyError(f"refusing to replace existing destination: {destination}")
    workspace_parent = destination.parent
    workspace_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{name}.assembly-", dir=workspace_parent)
    )
    shutil.rmtree(staging)
    try:
        _run(
            (
                "gh",
                "repo",
                "clone",
                f"{owner}/{name}",
                str(staging),
                "--",
                "--filter=blob:none",
                "--no-checkout",
            ),
            env=environment,
        )
        _run(
            ("git", "-C", str(staging), "fetch", "--depth", "1", "origin", ref),
            env=environment,
        )
        _run(
            ("git", "-C", str(staging), "checkout", "--detach", "FETCH_HEAD"),
            env=environment,
        )
        state = validate_repository(staging, name=name, owner=owner, ref="FETCH_HEAD")
        staging.rename(destination)
        return RepositoryState(head=state.head, origin=state.origin)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def _load_refs(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssemblyError(f"cannot read refs file {path}: {error}") from error
    if not isinstance(value, dict):
        raise AssemblyError("refs file must be a JSON object of repository to ref")
    refs: dict[str, str] = {}
    for name, ref in value.items():
        if not isinstance(name, str) or not REPOSITORY_NAME.fullmatch(name):
            raise AssemblyError(f"invalid repository name in refs file: {name!r}")
        if not isinstance(ref, str) or not ref.strip():
            raise AssemblyError(f"invalid ref for {name}: {ref!r}")
        refs[name] = ref.strip()
    return refs


def _required_ref(name: str, refs: Mapping[str, str], default_ref: str) -> str:
    return refs.get(name, default_ref)


def _receipt(
    requirements: Mapping[Path, Requirement],
    *,
    root: Path,
    workspace_parent: Path,
    owner: str,
    refs: Mapping[str, str],
    default_ref: str,
    states: Mapping[Path, RepositoryState],
) -> dict[str, Any]:
    repositories = []
    for requirement in sorted(requirements.values(), key=lambda item: item.name):
        state = states.get(requirement.destination)
        repositories.append(
            {
                "name": requirement.name,
                "destination": str(requirement.destination),
                "ref": _required_ref(requirement.name, refs, default_ref),
                "required_by": sorted(requirement.reasons),
                "state": "ready" if state is not None else "missing",
                "head": state.head if state is not None else None,
                "origin": state.origin if state is not None else None,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "owner": owner,
        "root": str(root),
        "workspace_parent": str(workspace_parent),
        "repositories": repositories,
    }


def _validate_present(
    requirements: Mapping[Path, Requirement],
    *,
    owner: str,
    refs: Mapping[str, str],
    default_ref: str,
) -> tuple[dict[Path, RepositoryState], list[Requirement]]:
    states: dict[Path, RepositoryState] = {}
    missing: list[Requirement] = []
    for requirement in sorted(requirements.values(), key=lambda item: item.name):
        if not requirement.destination.exists():
            missing.append(requirement)
            continue
        states[requirement.destination] = validate_repository(
            requirement.destination,
            name=requirement.name,
            owner=owner,
            ref=_required_ref(requirement.name, refs, default_ref),
        )
    return states, missing


def assemble(args: argparse.Namespace) -> dict[str, Any]:
    root = _resolved(args.root)
    workspace_parent = _resolved(args.workspace_parent or root.parent)
    if root.parent != workspace_parent:
        raise AssemblyError(
            f"root must be an exact child of workspace parent {workspace_parent}: {root}"
        )
    if not root.is_dir():
        raise AssemblyError(f"root repository does not exist: {root}")
    compose_files = [
        _resolved(path if path.is_absolute() else root / path)
        for path in args.compose_file
    ]
    for compose_file in compose_files:
        if not compose_file.is_file():
            raise AssemblyError(f"Compose file does not exist: {compose_file}")
    refs = _load_refs(args.refs_file)
    environment = dict(os.environ)

    while True:
        requirements = discover_graph(
            root, workspace_parent, compose_files, args.profile
        )
        states, missing = _validate_present(
            requirements,
            owner=args.owner,
            refs=refs,
            default_ref=args.ref,
        )
        if args.command == "plan":
            break
        if args.command == "verify":
            if missing:
                names = ", ".join(requirement.name for requirement in missing)
                raise AssemblyError(f"required repositories are missing: {names}")
            break
        if not missing:
            break
        if not environment.get("GH_TOKEN"):
            raise AssemblyError("GH_TOKEN is required to clone missing repositories")
        for requirement in missing:
            ref = _required_ref(requirement.name, refs, args.ref)
            print(
                f"assembling {args.owner}/{requirement.name}@{ref}", file=sys.stderr
            )
            states[requirement.destination] = clone_repository(
                requirement.destination,
                name=requirement.name,
                owner=args.owner,
                ref=ref,
                environment=environment,
            )

    return _receipt(
        requirements,
        root=root,
        workspace_parent=workspace_parent,
        owner=args.owner,
        refs=refs,
        default_ref=args.ref,
        states=states,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "checkout", "verify"))
    parser.add_argument(
        "--root", type=Path, default=Path.cwd(), help="root repository checkout"
    )
    parser.add_argument(
        "--workspace-parent",
        type=Path,
        help="parent directory that contains exact sibling repositories",
    )
    parser.add_argument("--owner", default="clavenar")
    parser.add_argument(
        "--ref", default="main", help="fallback ref for repositories not in --refs-file"
    )
    parser.add_argument(
        "--refs-file", type=Path, help="JSON object mapping repository names to exact refs"
    )
    parser.add_argument(
        "--compose-file",
        action="append",
        type=Path,
        default=[],
        help="Compose file to render for build/named contexts (repeatable)",
    )
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        help="Compose profile to enable while rendering (repeatable)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        receipt = assemble(parse_args(argv))
        json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    except AssemblyError as error:
        print(f"assembly error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
