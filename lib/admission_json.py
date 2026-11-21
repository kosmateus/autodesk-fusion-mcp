"""Strict JSON shared by the admission envelope and its exact input bytes."""

import json
import math


def decode_json(text):
    def reject_constant(value):
        raise ValueError("Non-JSON number")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("Non-finite JSON number")
        return number

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    return json.loads(text, parse_constant=reject_constant,
                      parse_float=finite_float, object_pairs_hook=unique_object)
