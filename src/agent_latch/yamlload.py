"""Line-aware YAML loading (SafeLoader only) for manifests and YAML prompt files."""

from __future__ import annotations

from typing import Any

import yaml


class LineDict(dict):
    """Mapping that remembers the source line of itself and of each key."""

    line: int = 1
    key_lines: dict[str, int]


class LineLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: LineLoader, node: yaml.MappingNode) -> LineDict:
    mapping = LineDict(loader.construct_mapping(node, deep=True))
    mapping.line = node.start_mark.line + 1
    mapping.key_lines = {
        str(key.value): key.start_mark.line + 1
        for key, _ in node.value
        if isinstance(key, yaml.ScalarNode)
    }
    return mapping


LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_yaml(text: str) -> Any:
    """Parse YAML with line tracking. Raises yaml.YAMLError on invalid input."""
    return yaml.load(text, Loader=LineLoader)  # SafeLoader subclass; never constructs objects


def line_of(mapping: Any, key: str) -> int:
    if isinstance(mapping, LineDict):
        return mapping.key_lines.get(key, mapping.line)
    return 1
