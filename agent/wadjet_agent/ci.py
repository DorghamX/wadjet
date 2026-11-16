"""Commit SHA and CI URL from the usual CI variables (section 11, step 3)."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path


def collect_ci_info(env: Mapping[str, str]) -> tuple[str | None, str | None]:
    """``(commit_sha, ci_url)`` from GITHUB_*, GITLAB_* or JENKINS_* env."""
    github_sha = env.get("GITHUB_SHA")
    if github_sha:
        server = env.get("GITHUB_SERVER_URL")
        repository = env.get("GITHUB_REPOSITORY")
        run_id = env.get("GITHUB_RUN_ID")
        url = None
        if server and repository and run_id:
            url = f"{server}/{repository}/actions/runs/{run_id}"
        return github_sha, url

    gitlab_sha = env.get("CI_COMMIT_SHA")
    if gitlab_sha:
        return gitlab_sha, env.get("CI_PIPELINE_URL") or env.get("CI_JOB_URL")

    jenkins_sha = env.get("GIT_COMMIT")
    if jenkins_sha:
        return jenkins_sha, env.get("BUILD_URL")

    return None, None


def git_commit(repo_root: Path) -> str | None:
    """Fallback: the checked-out commit, when git is available."""
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=repo_root,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None
