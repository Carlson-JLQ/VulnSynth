#!/usr/bin/env python3
"""
Generate diffs between vulnerable and fixed commits for CVEs.

This script reads CVE information from project_info.csv, clones the relevant
repositories, and generates diff files showing the changes between vulnerable
and fixed commits.

Usage:
    # Process a single CVE
    python get_cve_repos.py --cve CVE-2018-9159

    # Process multiple CVEs (comma-separated)
    python get_cve_repos.py --cves CVE-2018-9159,CVE-2016-9177

    # Process CVEs from a file (one CVE ID per line)
    python get_cve_repos.py --cve-file cves.txt

    # Process all CVEs
    python get_cve_repos.py --all

    # Force regenerate existing diffs
    python get_cve_repos.py --cve CVE-2018-9159 --force
"""

import os
import sys
import csv
import argparse
import subprocess
import shutil
import time
from pathlib import Path
from typing import List, Dict, Optional, Set

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
try:
    from src.config import PROJECT_INFO, CVES_PATH
except Exception:
    PROJECT_INFO = str(ROOT_DIR / "data" / "project_info.csv")
    CVES_PATH = str(ROOT_DIR / "cves")


DEFAULT_SKIPPED_CVES = {"CVE-2022-36007"}
DEFAULT_CVE_TIMEOUT_SECONDS = 1200


class CVEProcessingTimeout(TimeoutError):
    """Raised when a single CVE exceeds the configured processing time budget."""
    pass


def load_project_info() -> Dict[str, Dict]:
    """Load CVE project information from CSV file."""
    cve_data = {}
    with open(PROJECT_INFO, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row['cve_id']
            cve_data[cve_id] = {
                'github_username': row['github_username'],
                'github_repository_name': row['github_repository_name'],
                'github_url': row['github_url'],
                'buggy_commit_id': row['buggy_commit_id'],
                'fix_commit_ids': row['fix_commit_ids'].split(';') if row['fix_commit_ids'] else []
            }
    return cve_data


def run_text_command(command: List[str], cwd: Optional[str] = None,
                     check: bool = True, timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    """Run a subprocess and decode text output safely.

    Some repositories contain non-UTF-8 content in diffs or error messages.
    Using replacement decoding keeps long batch runs from crashing during the
    decode step while preserving most of the command output.
    """
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=check,
            timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        cmd_display = " ".join(command)
        timeout_text = f"{timeout:.1f}s" if timeout is not None else "the configured limit"
        raise CVEProcessingTimeout(
            f"Command timed out after {timeout_text}: {cmd_display}"
        ) from exc


def get_remaining_timeout(deadline: Optional[float]) -> Optional[float]:
    """Return remaining wall-clock budget for the current CVE."""
    if deadline is None:
        return None

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CVEProcessingTimeout("Exceeded per-CVE processing time budget")

    return remaining


def get_latest_commit(repo_path: str, commit_ids: List[str],
                      deadline: Optional[float] = None) -> Optional[str]:
    """
    Get the latest commit from a list of commit IDs based on commit timestamp.

    Args:
        repo_path: Path to the git repository
        commit_ids: List of commit SHA hashes

    Returns:
        The commit ID with the most recent timestamp, or None if none found
    """
    if not commit_ids:
        return None

    if len(commit_ids) == 1:
        return commit_ids[0]

    latest_commit = None
    latest_timestamp = 0

    for commit_id in commit_ids:
        try:
            result = run_text_command(
                ['git', 'show', '-s', '--format=%ct', commit_id],
                cwd=repo_path,
                check=True,
                timeout=get_remaining_timeout(deadline)
            )
            timestamp = int(result.stdout.strip())
            if timestamp > latest_timestamp:
                latest_timestamp = timestamp
                latest_commit = commit_id
        except (subprocess.CalledProcessError, ValueError) as e:
            print(f"  Warning: Could not get timestamp for commit {commit_id}: {e}")
            continue

    return latest_commit


def clone_repository(github_url: str, clone_dir: str,
                     deadline: Optional[float] = None) -> bool:
    """
    Clone a git repository.

    Args:
        github_url: URL of the GitHub repository
        clone_dir: Directory to clone into

    Returns:
        True if successful, False otherwise
    """
    # Some environments hang on GitHub repo URLs without the `.git` suffix.
    # Normalize clone URLs to improve reliability.
    def _normalize_clone_url(url: str) -> str:
        u = (url or "").strip()
        if not u:
            return u
        # Drop a single trailing slash to avoid `.../.git`.
        if u.endswith('/'):
            u = u[:-1]
        # Only append for GitHub HTTPS URLs; keep SSH / other hosts untouched.
        if u.startswith('https://github.com/') and not u.endswith('.git'):
            u = u + '.git'
        return u

    github_url = _normalize_clone_url(github_url)

    attempts = 3
    for attempt in range(1, attempts + 1):
        try:
            # Prefer a full clone to avoid missing objects during later diff/checkout
            # (partial/shallow clones can trigger large on-demand downloads and timeouts).
            command = ['git', 'clone', '--quiet', github_url, clone_dir]
            run_text_command(
                command,
                check=True,
                timeout=get_remaining_timeout(deadline)
            )
            return True
        except CVEProcessingTimeout:
            if os.path.exists(clone_dir):
                shutil.rmtree(clone_dir, ignore_errors=True)
            raise
        except subprocess.CalledProcessError as e:
            error_text = (e.stderr or str(e)).strip()
            print(f"  Error cloning repository (attempt {attempt}/{attempts}): {error_text}")

            if os.path.exists(clone_dir):
                shutil.rmtree(clone_dir, ignore_errors=True)

            if attempt < attempts:
                time.sleep(2 * attempt)

    return False


def commit_exists(repo_path: str, commit_id: str) -> bool:
    """Return True if the commit object exists locally."""
    result = subprocess.run(
        ['git', 'cat-file', '-e', f'{commit_id}^{{commit}}'],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    return result.returncode == 0


def fetch_commit(repo_path: str, commit_id: str,
                 deadline: Optional[float] = None) -> bool:
    """Fetch a specific commit, falling back to a broader fetch when needed."""
    if commit_exists(repo_path, commit_id):
        return True

    fetch_commands = [
        ['git', 'fetch', '--quiet', '--depth=1', 'origin', commit_id],
        ['git', 'fetch', '--quiet', '--depth=50', 'origin', commit_id],
        ['git', 'fetch', '--all', '--tags', '--quiet'],
    ]

    for command in fetch_commands:
        try:
            run_text_command(
                command,
                cwd=repo_path,
                check=True,
                timeout=get_remaining_timeout(deadline)
            )
        except subprocess.CalledProcessError as e:
            error_text = (e.stderr or str(e)).strip()
            print(f"  Warning: fetch failed for {commit_id[:12]} using {' '.join(command[2:])}: {error_text}")
            continue

        if commit_exists(repo_path, commit_id):
            return True

    return False


def ensure_commits_available(repo_path: str, commit_ids: List[str],
                             deadline: Optional[float] = None) -> List[str]:
    """Fetch any missing commits and return the subset that remain unavailable."""
    missing = []
    for commit_id in commit_ids:
        if not fetch_commit(repo_path, commit_id, deadline=deadline):
            missing.append(commit_id)
    return missing


def generate_diff(repo_path: str, vulnerable_commit: str, fix_commit: str,
                  deadline: Optional[float] = None) -> Optional[str]:
    """
    Generate a diff between vulnerable and fixed commits.

    Args:
        repo_path: Path to the git repository
        vulnerable_commit: SHA of the vulnerable commit
        fix_commit: SHA of the fix commit

    Returns:
        The diff as a string, or None if failed
    """
    try:
        result = run_text_command(
            ['git', 'diff', vulnerable_commit, fix_commit],
            cwd=repo_path,
            check=True,
            timeout=get_remaining_timeout(deadline)
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"  Error generating diff: {e.stderr}")
        return None


def process_cve(cve_id: str, cve_info: Dict, force: bool = False,
                timeout_seconds: Optional[int] = DEFAULT_CVE_TIMEOUT_SECONDS) -> bool:
    """
    Process a single CVE: clone repo, generate diff, save to file.

    Args:
        cve_id: The CVE identifier
        cve_info: Dictionary containing CVE project information
        force: Whether to regenerate even if files already exist

    Returns:
        True if successful, False otherwise
    """
    print(f"\nProcessing {cve_id}...")
    deadline = None if not timeout_seconds or timeout_seconds <= 0 else time.monotonic() + timeout_seconds

    # Create CVE directory
    cve_dir = os.path.join(CVES_PATH, cve_id)
    os.makedirs(cve_dir, exist_ok=True)

    diff_file = os.path.join(cve_dir, f"{cve_id}.diff")
    repo_name = cve_info['github_repository_name']
    repo_dir = os.path.join(cve_dir, repo_name)

    github_url = cve_info['github_url']
    vulnerable_commit = cve_info['buggy_commit_id']
    fix_commits = cve_info['fix_commit_ids']

    if not vulnerable_commit:
        print(f"  Error: No vulnerable commit specified for {cve_id}")
        return False

    if not fix_commits:
        print(f"  Error: No fix commits specified for {cve_id}")
        return False

    # Check if already complete
    if not force and os.path.exists(diff_file) and os.path.exists(repo_dir):
        print(f"  Already complete (diff and repo exist)")
        return True

    # Clone repository into CVE directory if not present
    if os.path.exists(repo_dir) and not os.path.exists(os.path.join(repo_dir, '.git')):
        print(f"  Removing incomplete repository directory: {repo_dir}")
        shutil.rmtree(repo_dir, ignore_errors=True)

    if not os.path.exists(repo_dir):
        print(f"  Cloning {github_url} into {repo_dir}...")
        if not clone_repository(github_url, repo_dir, deadline=deadline):
            return False
    else:
        print(f"  Repository already exists: {repo_dir}")

    # Fetch only the commits we need for this CVE, falling back to broader fetches.
    print(f"  Ensuring required commits are available...")
    missing_commits = ensure_commits_available(
        repo_dir,
        [vulnerable_commit] + fix_commits,
        deadline=deadline
    )
    if missing_commits:
        print(f"  Error: Could not fetch required commit(s): {', '.join(missing_commits)}")
        return False

    # Get the latest fix commit
    if len(fix_commits) > 1:
        print(f"  Multiple fix commits found ({len(fix_commits)}), selecting latest...")
        fix_commit = get_latest_commit(repo_dir, fix_commits, deadline=deadline)
        if not fix_commit:
            print(f"  Error: Could not determine latest fix commit")
            return False
        print(f"  Selected fix commit: {fix_commit[:12]}")
    else:
        fix_commit = fix_commits[0]

    # Generate diff
    if not os.path.exists(diff_file) or force:
        print(f"  Generating diff: {vulnerable_commit[:12]} -> {fix_commit[:12]}")
        diff_content = generate_diff(repo_dir, vulnerable_commit, fix_commit, deadline=deadline)

        if diff_content is None:
            return False

        if not diff_content.strip():
            print(f"  Warning: Empty diff generated")

        # Save diff to file
        with open(diff_file, 'w', encoding='utf-8') as f:
            f.write(diff_content)
        print(f"  Saved diff to: {diff_file}")
    else:
        print(f"  Diff file already exists: {diff_file}")

    # Checkout the vulnerable commit in the repo
    print(f"  Checking out vulnerable commit: {vulnerable_commit[:12]}")
    try:
        run_text_command(
            ['git', 'checkout', '--quiet', vulnerable_commit],
            cwd=repo_dir,
            check=True,
            timeout=get_remaining_timeout(deadline)
        )
    except subprocess.CalledProcessError as e:
        print(f"  Warning: Could not checkout vulnerable commit: {e.stderr}")

    print(f"  Complete: {cve_dir}")
    return True


def process_cves(cve_ids: List[str], cve_data: Dict[str, Dict],
                 force: bool = False,
                 skip_cves: Optional[Set[str]] = None,
                 timeout_seconds: Optional[int] = DEFAULT_CVE_TIMEOUT_SECONDS) -> Dict[str, Optional[bool]]:
    """
    Process multiple CVEs.

    Args:
        cve_ids: List of CVE identifiers to process
        cve_data: Dictionary of all CVE project information
        force: Whether to regenerate even if files already exist

    Returns:
        Dictionary mapping CVE IDs to success status
    """
    results: Dict[str, Optional[bool]] = {}
    skipped = skip_cves or set()

    for cve_id in cve_ids:
        if cve_id not in cve_data:
            print(f"\nWarning: {cve_id} not found in project_info.csv")
            results[cve_id] = False
            continue

        if cve_id in skipped:
            print(f"\nSkipping {cve_id} (configured skip list)")
            results[cve_id] = None
            continue

        try:
            success = process_cve(
                cve_id,
                cve_data[cve_id],
                force=force,
                timeout_seconds=timeout_seconds
            )
        except CVEProcessingTimeout as exc:
            print(f"  Skipping {cve_id} after timeout: {exc}")
            success = None
        except Exception as exc:
            print(f"  Unexpected error while processing {cve_id}: {exc}")
            success = False
        results[cve_id] = success

    return results


def main():
    parser = argparse.ArgumentParser(
        description='Generate diffs between vulnerable and fixed commits for CVEs'
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--cve',
        type=str,
        help='Process a single CVE (e.g., CVE-2018-9159)'
    )
    group.add_argument(
        '--cves',
        type=str,
        help='Process multiple CVEs, comma-separated (e.g., CVE-2018-9159,CVE-2016-9177)'
    )
    group.add_argument(
        '--cve-file',
        type=str,
        help='Process CVEs from a file (one CVE ID per line)'
    )
    group.add_argument(
        '--all',
        action='store_true',
        help='Process all CVEs in project_info.csv'
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='Regenerate diffs even if they already exist'
    )
    parser.add_argument(
        '--skip-cves',
        type=str,
        default='',
        help='Additional CVE IDs to skip, comma-separated'
    )
    parser.add_argument(
        '--timeout-seconds',
        type=int,
        default=DEFAULT_CVE_TIMEOUT_SECONDS,
        help='Per-CVE timeout in seconds; use 0 to disable (default: 600)'
    )

    args = parser.parse_args()

    # Load CVE data
    print("Loading project information...")
    cve_data = load_project_info()
    print(f"Loaded {len(cve_data)} CVEs from {PROJECT_INFO}")

    # Determine which CVEs to process
    if args.cve:
        cve_ids = [args.cve]
    elif args.cves:
        cve_ids = [cve.strip() for cve in args.cves.split(',')]
    elif args.cve_file:
        with open(args.cve_file, 'r', encoding='utf-8') as f:
            cve_ids = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:  # args.all
        cve_ids = list(cve_data.keys())

    skip_cves = set(DEFAULT_SKIPPED_CVES)
    if args.skip_cves:
        skip_cves.update(cve.strip() for cve in args.skip_cves.split(',') if cve.strip())

    print(f"\nWill process {len(cve_ids)} CVE(s)")
    if skip_cves:
        print(f"Skipping {len(skip_cves)} CVE(s) by configuration: {', '.join(sorted(skip_cves))}")

    if args.force:
        print("Force mode enabled - will regenerate existing diffs")

    if args.timeout_seconds > 0:
        print(f"Per-CVE timeout enabled: {args.timeout_seconds} seconds")
    else:
        print("Per-CVE timeout disabled")

    # Process CVEs
    results = process_cves(
        cve_ids,
        cve_data,
        force=args.force,
        skip_cves=skip_cves,
        timeout_seconds=args.timeout_seconds
    )

    # Print summary
    successful = sum(1 for success in results.values() if success is True)
    skipped = sum(1 for success in results.values() if success is None)
    failed = sum(1 for success in results.values() if success is False)

    print("\n" + "=" * 60)
    print("Summary:")
    print(f"  Total CVEs processed: {len(results)}")
    print(f"  Successful: {successful}")
    print(f"  Skipped: {skipped}")
    print(f"  Failed: {failed}")

    if failed > 0:
        print("\nFailed CVEs:")
        for cve_id, success in results.items():
            if not success:
                print(f"  - {cve_id}")

    if skipped > 0:
        print("\nSkipped CVEs:")
        for cve_id, success in results.items():
            if success is None:
                print(f"  - {cve_id}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())
