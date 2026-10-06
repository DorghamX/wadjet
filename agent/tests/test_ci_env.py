"""Commit SHA and CI URL collection (section 11, step 3)."""

from __future__ import annotations

from pathlib import Path

from wadjet_agent.ci import collect_ci_info, git_commit


def test_github_actions() -> None:
    sha, url = collect_ci_info(
        {
            "GITHUB_SHA": "abc123",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "acme/widget",
            "GITHUB_RUN_ID": "42",
        }
    )
    assert sha == "abc123"
    assert url == "https://github.com/acme/widget/actions/runs/42"


def test_github_without_run_details() -> None:
    sha, url = collect_ci_info({"GITHUB_SHA": "abc123"})
    assert sha == "abc123"
    assert url is None


def test_gitlab() -> None:
    sha, url = collect_ci_info(
        {"CI_COMMIT_SHA": "def456", "CI_PIPELINE_URL": "https://gitlab.com/a/b/-/pipelines/7"}
    )
    assert sha == "def456"
    assert url == "https://gitlab.com/a/b/-/pipelines/7"

    sha, url = collect_ci_info({"CI_COMMIT_SHA": "def456", "CI_JOB_URL": "https://j"})
    assert (sha, url) == ("def456", "https://j")


def test_jenkins() -> None:
    sha, url = collect_ci_info({"GIT_COMMIT": "789abc", "BUILD_URL": "https://ci/job/1"})
    assert sha == "789abc"
    assert url == "https://ci/job/1"


def test_no_ci_environment() -> None:
    assert collect_ci_info({}) == (None, None)
    assert collect_ci_info({"PATH": "/usr/bin"}) == (None, None)


def test_github_wins_over_jenkins_style_variables() -> None:
    sha, _ = collect_ci_info({"GITHUB_SHA": "aaa", "GIT_COMMIT": "bbb"})
    assert sha == "aaa"


def test_git_commit_fallback(tmp_path: Path) -> None:
    assert git_commit(tmp_path) is None  # not a repository


def test_git_commit_in_a_repository() -> None:
    sha = git_commit(Path(__file__).parent.parent)
    # Either git is unavailable/not a repo (None) or a full hex sha.
    assert sha is None or (len(sha) == 40 and all(c in "0123456789abcdef" for c in sha))
