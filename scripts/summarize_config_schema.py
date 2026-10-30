#!/usr/bin/env python3

import os
import sys

_DIRPATH = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_DIRPATH), "lib"))

_DEFERRED = {
    "applications": "see \"APPLICATION_SCHEMAS_BY_TYPE\" below, dispatched by each entry's own \"type\"",
    "events": "see \"EVENT_SCHEMAS_BY_TYPE\" below, dispatched by each entry's own \"type\"",
}


class Color:
    BOLD = "\033[1m"
    RESET = "\033[0m"

    def __init__(self, enabled):
        self.enabled = enabled

    def wrap(self, code, text):
        if not self.enabled:
            return text
        return "{}{}{}".format(code, text, self.RESET)

    def bold(self, text):
        return self.wrap(self.BOLD, text)

from config_schema import CONFIG_SCHEMA, APPLICATION_SCHEMAS_BY_TYPE, EVENT_SCHEMAS_BY_TYPE


def _describeSchema(schema):
    parts = []
    t = schema.get("type")
    if t:
        parts.append("type: {}".format(t))
    if "const" in schema:
        parts.append("const: {!r}".format(schema["const"]))
    if "enum" in schema:
        parts.append("enum: {!r}".format(schema["enum"]))
    if "minItems" in schema:
        parts.append("minItems: {}".format(schema["minItems"]))
    if "maxItems" in schema:
        parts.append("maxItems: {}".format(schema["maxItems"]))
    if "minimum" in schema:
        parts.append("minimum: {} [not enforced by ConfigValidator]".format(schema["minimum"]))
    if t == "object":
        additional = schema.get("additionalProperties", True)
        if additional is False:
            parts.append("no other properties allowed")
        elif additional is True:
            parts.append("any other property also allowed, unvalidated")
        # additional as a dict is shown via the "<any key>" child instead, see _childrenOf.
    return ", ".join(parts)


def _childrenOf(schema, defer):
    # Returns a list of (label, child_schema, deferred_note) triples - defer_note is None
    # unless this child's key is one of "defer"'s (see _DEFERRED above).
    children = []
    t = schema.get("type")
    if t == "object":
        required = set(schema.get("required", []))
        for key, child_schema in schema.get("properties", {}).items():
            marker = "required" if key in required else "optional"
            children.append(("{} [{}]".format(key, marker), child_schema, defer.get(key)))
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            children.append(("<any key>", additional, None))
    elif t == "array":
        items = schema.get("items")
        if items is not None:
            children.append(("[each item]", items, None))
    return children


def _printSchemaTree(label, schema, prefix, is_last, is_root, out, defer):
    desc = _describeSchema(schema)
    text = "{} - {}".format(label, desc) if desc else label
    line = text if is_root else prefix + ("└── " if is_last else "├── ") + text
    out.append(line)

    child_prefix = "" if is_root else prefix + ("    " if is_last else "│   ")
    children = _childrenOf(schema, defer)
    for i, (child_label, child_schema, note) in enumerate(children):
        is_last_child = (i == len(children) - 1)
        if note:
            connector = "└── " if is_last_child else "├── "
            out.append("{}{}{} - {}".format(child_prefix, connector, child_label, note))
            continue
        _printSchemaTree(child_label, child_schema, child_prefix, is_last_child, False, out, defer)


def buildSchemaLines(color=None):
    if color is None:
        color = Color(enabled=False)
    out = ["", color.bold("** CONFIG_SCHEMA **"), ""]
    _printSchemaTree("CONFIG_SCHEMA", CONFIG_SCHEMA, "", True, True, out, _DEFERRED)
    out.append("")

    out.append(color.bold("** APPLICATION_SCHEMAS_BY_TYPE **"))
    out.append("")
    for app_type in sorted(APPLICATION_SCHEMAS_BY_TYPE):
        _printSchemaTree(app_type, APPLICATION_SCHEMAS_BY_TYPE[app_type], "", True, True, out, {})
        out.append("")

    out.append(color.bold("** EVENT_SCHEMAS_BY_TYPE **"))
    out.append("")
    for event_type in sorted(EVENT_SCHEMAS_BY_TYPE):
        _printSchemaTree(event_type, EVENT_SCHEMAS_BY_TYPE[event_type], "", True, True, out, {})
        out.append("")

    return out


def main():
    no_color = "--no-color" in sys.argv[1:]
    color = Color(enabled=not no_color and sys.stdout.isatty())
    for line in buildSchemaLines(color):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
