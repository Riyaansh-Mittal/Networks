
class ValidationError:
    def __init__(self, message, path):
        self.message = message
        self.path = list(path)
        self.absolute_path = list(path)

class ConfigValidator:
    def __init__(self, schema):
        self._schema = schema

    def iter_errors(self, instance):
        yield from self._validate(self._schema, instance, [])

    def is_valid(self, instance):
        return next(self.iter_errors(instance), None) is None

    def _validate(self, schema, instance, path):
        if "type" in schema and not self._matches_type(instance, schema["type"]):
            yield ValidationError(
                "{!r} is not of type {!r}".format(instance, schema["type"]), path)
            return  # further keywords all assume the right type, so stop here

        if "const" in schema and instance != schema["const"]:
            yield ValidationError("{!r} was expected".format(schema["const"]), path)

        if "enum" in schema and instance not in schema["enum"]:
            yield ValidationError("{!r} is not one of {!r}".format(instance, schema["enum"]), path)

        if isinstance(instance, dict):
            yield from self._validate_object(schema, instance, path)
        elif isinstance(instance, list):
            yield from self._validate_array(schema, instance, path)

    def _validate_object(self, schema, instance, path):
        for key in schema.get("required", []):
            if key not in instance:
                yield ValidationError("{!r} is a required property".format(key), path)

        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in properties:
                yield from self._validate(properties[key], value, path + [key])
            elif additional is False:
                yield ValidationError(
                    "Additional properties are not allowed ({!r} was unexpected)".format(key), path)
            elif isinstance(additional, dict):
                yield from self._validate(additional, value, path + [key])

    def _validate_array(self, schema, instance, path):
        min_items = schema.get("minItems")
        if min_items is not None and len(instance) < min_items:
            yield ValidationError(
                "{!r} is too short - must have at least {} item(s)".format(instance, min_items), path)

        max_items = schema.get("maxItems")
        if max_items is not None and len(instance) > max_items:
            yield ValidationError(
                "{!r} is too long - must have at most {} item(s)".format(instance, max_items), path)

        items_schema = schema.get("items")
        if items_schema is not None:
            for i, item in enumerate(instance):
                yield from self._validate(items_schema, item, path + [i])

    @staticmethod
    def _matches_type(instance, type_name):
        if type_name == "object":
            return isinstance(instance, dict)
        if type_name == "array":
            return isinstance(instance, list)
        if type_name == "string":
            return isinstance(instance, str)
        if type_name == "integer":
            return isinstance(instance, int) and not isinstance(instance, bool)
        if type_name == "number":
            return isinstance(instance, (int, float)) and not isinstance(instance, bool)
        if type_name == "boolean":
            return isinstance(instance, bool)
        if type_name == "null":
            return instance is None
        return True

_A_RECORDS = {
    "type": "object",
    "additionalProperties": {
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": ["ip", "ttl"],
            "properties": {
                "ip": {"type": "string"},
                "ttl": {"type": "integer", "minimum": 0},
            },
        },
    },
}

_NS_RECORDS = {
    "type": "object",
    "additionalProperties": {
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "ip"],
            "properties": {
                "name": {"type": "string"},
                "ip": {"type": "string"},
                "ipttl": {"type": "integer", "minimum": 0},
                "namettl": {"type": "integer", "minimum": 0},
            },
        },
    },
}

_CNAME_RECORDS = {
    "type": "object",
    "additionalProperties": {
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": ["alias", "ttl"],
            "properties": {
                "alias": {"type": "string"},
                "ttl": {"type": "integer", "minimum": 0},
            },
        },
    },
}

_ROOT_NAMESERVER = {
    "type": "object",
    "additionalProperties": False,
    "required": ["ip", "port", "ttl"],
    "properties": {
        "name": {"type": "string"},
        "ip": {"type": "string"},
        "port": {"type": "integer"},
        "ttl": {"type": "integer", "minimum": 0},
    },
}

_LINK_PROPERTIES = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "delay": {"type": "integer", "minimum": 0},
    },
}

_LINK_ID_PAIR = {"type": "array", "items": {"type": "string"}, "minItems": 2, "maxItems": 2}

def _build_application_schema(extra_properties=None):
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["eId", "type", "port"],
        "properties": {
            "eId": {"type": "string"},
            "type": {"type": "string"},
            "port": {"type": "integer"},
            **(extra_properties or {}),
        },
    }

_NO_PARAMETERS_APPLICATION = _build_application_schema()

APPLICATION_SCHEMAS_BY_TYPE = {
    "SenderApplication": _NO_PARAMETERS_APPLICATION,
    "SinkApplication": _NO_PARAMETERS_APPLICATION,
    "DnsClient": _NO_PARAMETERS_APPLICATION,
    "ContentClient": _NO_PARAMETERS_APPLICATION,
    "AuthoritativeNameServer": _build_application_schema({
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "records A": _A_RECORDS,
                "records NS": _NS_RECORDS,
                "records CNAME": _CNAME_RECORDS,
                "zones": {"type": "array", "items": {"type": "string"}},
                "zone admin": {"type": "string"},
            },
        },
    }),
    "LocalNameServer": _build_application_schema({
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "root nameserver": _ROOT_NAMESERVER,
            },
        },
    }),
}

def _build_event_schema(required_extra, properties_extra):
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["type", "time"] + required_extra,
        "properties": {
            "type": {"type": "string"},
            "time": {"type": "integer"},
            **properties_extra,
        },
    }

_UPLINK_DOWNLINK_EVENT = _build_event_schema(["link"], {"link": _LINK_ID_PAIR})

EVENT_SCHEMAS_BY_TYPE = {
    "uplink": _UPLINK_DOWNLINK_EVENT,
    "downlink": _UPLINK_DOWNLINK_EVENT,
    "stop": _build_event_schema([], {}),
    "allowserverfails": _build_event_schema([], {}),
    "dumpnetwork": _build_event_schema(["args"], {"args": {"type": "string"}}),
    "sendquery": _build_event_schema(
        ["src", "src_port", "dst", "dst_port", "dnsName", "questionType"],
        {
            "src": {"type": "string"},
            "src_port": {"type": "integer"},
            "dst": {"type": "string"},
            "dst_port": {"type": "integer"},
            "dnsName": {"type": "string"},
            "questionType": {"type": "string"},
        },
    ),
    "accesscontent": _build_event_schema(
        ["src", "src_port", "dst", "dst_port", "dnsName", "questionType"],
        {
            "src": {"type": "string"},
            "src_port": {"type": "integer"},
            "dst": {"type": "string"},
            "dst_port": {"type": "integer"},
            "dnsName": {"type": "string"},
            "questionType": {"type": "string"},
            "neededServers": {"type": "integer", "minimum": 1},
            "duration": {"type": "integer", "minimum": 1},
        },
    ),
    "sendpackets": _build_event_schema(
        ["src", "src_port", "dst", "dst_port", "num_packets"],
        {
            "src": {"type": "string"},
            "src_port": {"type": "integer"},
            "dst": {"type": "string"},
            "dst_port": {"type": "integer"},
            "num_packets": {"type": "integer"},
        },
    ),
}

CONFIG_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Simulator configuration",
    "type": "object",
    "additionalProperties": False,
    "required": ["network", "endhosts", "network-links", "applications", "events"],
    "properties": {
        "network": {
            "type": "object",
            "additionalProperties": False,
            "required": ["nId"],
            "properties": {
                "nId": {"type": "string"},
            },
        },
        "endhosts": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["eId", "ipAddress"],
                "properties": {
                    "eId": {"type": "string"},
                    "ipAddress": {"type": "string"},
                    "contentServers": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        "network-links": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "interfaces", "interface_ips", "status"],
                "properties": {
                    "id": {"type": "string"},
                    "interfaces": _LINK_ID_PAIR,
                    "interface_ips": _LINK_ID_PAIR,
                    "status": {"enum": ["up", "down"]},
                    "properties": _LINK_PROPERTIES,
                },
            },
        },
        "applications": {"type": "array", "items": {"type": "object"}},
        "events": {"type": "array", "items": {"type": "object"}},
    },
}
