"""路径 glob 匹配与收窄原语的单元测试。"""
from __future__ import annotations

import pytest

from app.security import pattern_covers, request_path_matches


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("/files/**", "/files", True),
        ("/files/**", "/files/a/b/c", True),
        ("/files/*", "/files/a", True),
        ("/files/*", "/files/a/b", False),
        ("/files/reports/*/x", "/files/reports/2026/x", True),
        ("/a/b/c", "/a/b/c", True),
        ("/a/b/c", "/a/b/d", False),
        ("/", "/", True),
    ],
)
def test_request_path_glob(pattern, path, expected):
    assert request_path_matches(pattern, path) is expected


@pytest.mark.parametrize(
    "child,parent,expected",
    [
        ("/files/reports/**", "/files/**", True),
        ("/files/reports/2026/x", "/files/reports/**", True),
        ("/files/reports/*", "/files/**", True),
        ("/files/reports/*", "/files/*", False),
        ("/files/a", "/files/*", True),
        ("/files/*", "/files/a", False),
        ("/elsewhere/**", "/files/**", False),
        ("/a/b/c", "/a/*/c", True),
        ("/a/**", "/a/*", False),
        ("/files/**", "/files/**", True),
        ("/files/reports/2026/x", "/files/reports/*", False),
        ("/files", "/files/**", True),
    ],
)
def test_narrowing(child, parent, expected):
    assert pattern_covers(child, parent) is expected
