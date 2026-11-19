"""Multi-Unit & Currency Converter Plugin for Helm.

Provides safe mathematical evaluation (AST-based, no eval), global currency conversion,
timezone conversion, and physical/digital unit conversion.
"""

from __future__ import annotations

import ast
import math
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("helm.plugins.converter")

try:
    from helm_plugin_sdk import HelmPlugin, PluginContext, PluginTool, PluginCommand
except ImportError:
    class HelmPlugin:  # type: ignore
        def __init__(self, context: Any): self.context = context
        def initialize(self): pass
        def shutdown(self): pass
        def get_tools(self): return []
        def get_commands(self): return []
    PluginContext = Any  # type: ignore
    PluginTool = Any  # type: ignore
    PluginCommand = Any  # type: ignore


# ---------------------------------------------------------------------------
# Safe AST Math Evaluator
# ---------------------------------------------------------------------------

_ALLOWED_MATH_FUNCS = {
    "sqrt": math.sqrt,
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "asin": math.asin,
    "acos": math.acos,
    "atan": math.atan,
    "log": math.log,
    "log10": math.log10,
    "log2": math.log2,
    "exp": math.exp,
    "abs": abs,
    "round": round,
    "ceil": math.ceil,
    "floor": math.floor,
}

_ALLOWED_MATH_CONSTANTS = {
    "pi": math.pi,
    "e": math.e,
    "tau": math.tau,
}


def _eval_ast_node(node: ast.AST) -> Union[int, float]:
    """Recursively evaluates safe AST math expressions."""
    if isinstance(node, ast.Expression):
        return _eval_ast_node(node.body)

    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError(f"Unsupported constant type: {type(node.value)}")

    # Python < 3.8 compat
    if hasattr(ast, "Num") and isinstance(node, ast.Num):  # type: ignore
        return node.n  # type: ignore

    if isinstance(node, ast.Name):
        var_name = node.id.lower()
        if var_name in _ALLOWED_MATH_CONSTANTS:
            return _ALLOWED_MATH_CONSTANTS[var_name]
        raise ValueError(f"Unknown constant or variable '{node.id}'.")

    if isinstance(node, ast.UnaryOp):
        operand = _eval_ast_node(node.operand)
        if isinstance(node.op, ast.UAdd):
            return +operand
        if isinstance(node.op, ast.USub):
            return -operand
        raise ValueError(f"Unsupported unary operator: {type(node.op)}")

    if isinstance(node, ast.BinOp):
        left = _eval_ast_node(node.left)
        right = _eval_ast_node(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            if right == 0:
                raise ZeroDivisionError("Division by zero")
            return left / right
        if isinstance(node.op, ast.FloorDiv):
            if right == 0:
                raise ZeroDivisionError("Integer division by zero")
            return left // right
        if isinstance(node.op, ast.Mod):
            if right == 0:
                raise ZeroDivisionError("Modulo by zero")
            return left % right
        if isinstance(node.op, ast.Pow):
            # Guard against enormous exponent computation
            if right > 1000 or left > 10000:
                raise OverflowError("Exponentiation exceeds safety limits")
            return left ** right
        raise ValueError(f"Unsupported binary operator: {type(node.op)}")

    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ValueError("Only direct function calls are allowed.")
        func_name = node.func.id.lower()
        if func_name not in _ALLOWED_MATH_FUNCS:
            raise ValueError(f"Function '{func_name}' is not permitted.")
        args = [_eval_ast_node(arg) for arg in node.args]
        return _ALLOWED_MATH_FUNCS[func_name](*args)

    raise ValueError(f"Unsupported expression syntax: {type(node).__name__}")


def evaluate_math(expression: str, **kwargs) -> Dict[str, Any]:
    """Safely evaluate mathematical expressions using AST parsing."""
    raw = (expression or "").strip()
    if not raw:
        return {"ok": False, "error": "Expression cannot be empty."}

    # Replace ^ with ** for intuitive power notation
    clean_expr = raw.replace("^", "**")

    try:
        parsed = ast.parse(clean_expr, mode="eval")
        result = _eval_ast_node(parsed)
        # Format floating points nicely
        if isinstance(result, float) and result.is_integer():
            result = int(result)
        elif isinstance(result, float):
            result = round(result, 8)

        return {
            "ok": True,
            "expression": raw,
            "result": result,
            "formatted": f"{raw} = {result}",
        }
    except Exception as e:
        return {"ok": False, "expression": raw, "error": f"Evaluation error: {e}"}


# ---------------------------------------------------------------------------
# Currency Converter
# ---------------------------------------------------------------------------

_FX_RATES_TO_USD: Dict[str, float] = {
    "USD": 1.0,
    "EUR": 0.92,
    "GBP": 0.79,
    "JPY": 154.50,
    "CAD": 1.36,
    "AUD": 1.52,
    "CHF": 0.90,
    "CNY": 7.23,
    "INR": 83.20,
    "SGD": 1.35,
    "BRL": 5.15,
    "MXN": 16.80,
    "KRW": 1370.0,
    "NZD": 1.64,
}


def convert_currency(
    amount: float,
    from_currency: str,
    to_currency: str,
    **kwargs
) -> Dict[str, Any]:
    """Convert amount between world currencies."""
    f_cur = (from_currency or "").strip().upper()
    t_cur = (to_currency or "").strip().upper()

    if f_cur not in _FX_RATES_TO_USD:
        return {"ok": False, "error": f"Unknown currency '{f_cur}'. Supported: {list(_FX_RATES_TO_USD.keys())}"}
    if t_cur not in _FX_RATES_TO_USD:
        return {"ok": False, "error": f"Unknown currency '{t_cur}'. Supported: {list(_FX_RATES_TO_USD.keys())}"}

    try:
        val = float(amount)
    except (ValueError, TypeError):
        return {"ok": False, "error": f"Invalid numeric amount '{amount}'."}

    rate = _FX_RATES_TO_USD[t_cur] / _FX_RATES_TO_USD[f_cur]
    converted = round(val * rate, 4)

    return {
        "ok": True,
        "amount": val,
        "from_currency": f_cur,
        "to_currency": t_cur,
        "converted": converted,
        "rate": round(rate, 6),
        "formatted": f"{val:,.2f} {f_cur} = {converted:,.2f} {t_cur}",
    }


# ---------------------------------------------------------------------------
# Timezone Converter
# ---------------------------------------------------------------------------

_TZ_OFFSETS_HOURS: Dict[str, float] = {
    "UTC": 0.0,
    "GMT": 0.0,
    "BST": 1.0,
    "CET": 1.0,
    "CEST": 2.0,
    "EET": 2.0,
    "EEST": 3.0,
    "MSK": 3.0,
    "IST": 5.5,
    "JST": 9.0,
    "KST": 9.0,
    "AEST": 10.0,
    "AEDT": 11.0,
    "NZST": 12.0,
    "EST": -5.0,
    "EDT": -4.0,
    "CST": -6.0,
    "CDT": -5.0,
    "MST": -7.0,
    "MDT": -6.0,
    "PST": -8.0,
    "PDT": -7.0,
    "HST": -10.0,
}


def convert_timezone(
    from_tz: str,
    to_tz: str,
    time_str: str = "now",
    **kwargs
) -> Dict[str, Any]:
    """Convert time from one timezone abbreviation to another."""
    f_tz = (from_tz or "").strip().upper()
    t_tz = (to_tz or "").strip().upper()

    if f_tz not in _TZ_OFFSETS_HOURS:
        return {"ok": False, "error": f"Unknown timezone '{f_tz}'. Supported: {list(_TZ_OFFSETS_HOURS.keys())}"}
    if t_tz not in _TZ_OFFSETS_HOURS:
        return {"ok": False, "error": f"Unknown timezone '{t_tz}'. Supported: {list(_TZ_OFFSETS_HOURS.keys())}"}

    f_offset = _TZ_OFFSETS_HOURS[f_tz]
    t_offset = _TZ_OFFSETS_HOURS[t_tz]
    delta_hours = t_offset - f_offset

    raw_t = (time_str or "now").strip().lower()

    if raw_t == "now":
        now_utc = datetime.now(timezone.utc)
        target_time = now_utc + timedelta(hours=t_offset)
        source_time = now_utc + timedelta(hours=f_offset)
        return {
            "ok": True,
            "source_time": source_time.strftime("%Y-%m-%d %H:%M:%S") + f" {f_tz}",
            "target_time": target_time.strftime("%Y-%m-%d %H:%M:%S") + f" {t_tz}",
            "from_tz": f_tz,
            "to_tz": t_tz,
            "offset_difference_hours": delta_hours,
        }

    # Attempt parsing HH:MM
    try:
        parts = raw_t.split(":")
        hours = int(parts[0])
        minutes = int(parts[1]) if len(parts) > 1 else 0
        total_minutes = hours * 60 + minutes + int(delta_hours * 60)
        total_minutes = total_minutes % (24 * 60)
        target_h = total_minutes // 60
        target_m = total_minutes % 60
        res_str = f"{target_h:02d}:{target_m:02d}"
        return {
            "ok": True,
            "source_time": f"{hours:02d}:{minutes:02d} {f_tz}",
            "target_time": f"{res_str} {t_tz}",
            "from_tz": f_tz,
            "to_tz": t_tz,
            "offset_difference_hours": delta_hours,
        }
    except Exception as e:
        return {"ok": False, "error": f"Failed to parse time '{time_str}': {e}"}


# ---------------------------------------------------------------------------
# Unit Converter
# ---------------------------------------------------------------------------

_UNIT_CONVERSIONS: Dict[str, Dict[str, float]] = {
    "length": {
        "m": 1.0,
        "km": 1000.0,
        "cm": 0.01,
        "mm": 0.001,
        "mi": 1609.344,
        "yd": 0.9144,
        "ft": 0.3048,
        "in": 0.0254,
    },
    "mass": {
        "kg": 1.0,
        "g": 0.001,
        "mg": 0.000001,
        "lb": 0.45359237,
        "oz": 0.028349523,
    },
    "data": {
        "b": 1.0,
        "kb": 1024.0,
        "mb": 1024.0 ** 2,
        "gb": 1024.0 ** 3,
        "tb": 1024.0 ** 4,
    },
}


def convert_units(
    value: float,
    from_unit: str,
    to_unit: str,
    **kwargs
) -> Dict[str, Any]:
    """Convert value across length, mass, temperature, or data units."""
    f_u = (from_unit or "").strip().lower()
    t_u = (to_unit or "").strip().lower()

    try:
        val = float(value)
    except (ValueError, TypeError):
        return {"ok": False, "error": f"Invalid numeric value '{value}'."}

    # Temperature conversion
    temp_units = {"c", "f", "k"}
    if f_u in temp_units and t_u in temp_units:
        # Normalize to Celsius
        if f_u == "c":
            celsius = val
        elif f_u == "f":
            celsius = (val - 32) * 5 / 9
        else:  # k
            celsius = val - 273.15

        # Convert to target
        if t_u == "c":
            result = celsius
        elif t_u == "f":
            result = (celsius * 9 / 5) + 32
        else:  # k
            result = celsius + 273.15

        res_rounded = round(result, 4)
        return {
            "ok": True,
            "category": "temperature",
            "value": val,
            "from_unit": f_u.upper(),
            "to_unit": t_u.upper(),
            "converted": res_rounded,
            "formatted": f"{val} {f_u.upper()} = {res_rounded} {t_u.upper()}",
        }

    # Length, mass, data conversion
    for category, table in _UNIT_CONVERSIONS.items():
        if f_u in table and t_u in table:
            base_val = val * table[f_u]
            result = base_val / table[t_u]
            res_rounded = round(result, 6)
            return {
                "ok": True,
                "category": category,
                "value": val,
                "from_unit": f_u,
                "to_unit": t_u,
                "converted": res_rounded,
                "formatted": f"{val} {f_u} = {res_rounded} {t_u}",
            }

    return {
        "ok": False,
        "error": f"Incompatible or unsupported unit pair '{from_unit}' -> '{to_unit}'.",
    }


# ---------------------------------------------------------------------------
# ConverterPlugin Class Implementation
# ---------------------------------------------------------------------------

class ConverterPlugin(HelmPlugin):
    """Multi-Unit & Currency Converter Plugin for Helm."""

    def initialize(self) -> None:
        self.logger.info("Initializing Multi-Unit & Currency Converter Plugin")

    def shutdown(self) -> None:
        self.logger.info("Shutting down Converter Plugin")

    def get_tools(self) -> List[PluginTool]:
        return [
            PluginTool(
                name="evaluate_math",
                description="Safely evaluate a mathematical expression (supports trigonometry, powers, logs, and constants without eval).",
                handler=evaluate_math,
                parameters={
                    "type": "object",
                    "properties": {
                        "expression": {"type": "string", "description": "Formula to evaluate (e.g. 'sqrt(144) + 2^3')"}
                    },
                    "required": ["expression"]
                },
                required_permissions=["system"],
                capability_tier="READ_ONLY",
            ),
            PluginTool(
                name="convert_currency",
                description="Convert money between global currencies (USD, EUR, GBP, JPY, CAD, AUD, INR, etc.).",
                handler=convert_currency,
                parameters={
                    "type": "object",
                    "properties": {
                        "amount": {"type": "number", "description": "Amount"},
                        "from_currency": {"type": "string", "description": "Source currency (e.g. 'USD')"},
                        "to_currency": {"type": "string", "description": "Target currency (e.g. 'EUR')"}
                    },
                    "required": ["amount", "from_currency", "to_currency"]
                },
                required_permissions=["system"],
                capability_tier="READ_ONLY",
            ),
            PluginTool(
                name="convert_timezone",
                description="Convert a timestamp or hour from one timezone to another.",
                handler=convert_timezone,
                parameters={
                    "type": "object",
                    "properties": {
                        "from_tz": {"type": "string", "description": "Source timezone code"},
                        "to_tz": {"type": "string", "description": "Target timezone code"},
                        "time_str": {"type": "string", "description": "Time string (e.g. '14:30' or 'now')"}
                    },
                    "required": ["from_tz", "to_tz"]
                },
                required_permissions=["system"],
                capability_tier="READ_ONLY",
            ),
            PluginTool(
                name="convert_units",
                description="Convert physical values across units of length, mass/weight, temperature, or data storage.",
                handler=convert_units,
                parameters={
                    "type": "object",
                    "properties": {
                        "value": {"type": "number", "description": "Value to convert"},
                        "from_unit": {"type": "string", "description": "Source unit"},
                        "to_unit": {"type": "string", "description": "Target unit"}
                    },
                    "required": ["value", "from_unit", "to_unit"]
                },
                required_permissions=["system"],
                capability_tier="READ_ONLY",
            ),
        ]

    def get_commands(self) -> List[PluginCommand]:
        return [
            PluginCommand(
                id="evaluate_math",
                title="Math Calculator",
                description="Calculate formula",
                handler=evaluate_math,
                shortcut="Ctrl+Shift+M",
            ),
            PluginCommand(
                id="convert_currency",
                title="Currency Conversion",
                description="Convert currency",
                handler=convert_currency,
                shortcut="Ctrl+Shift+C",
            ),
            PluginCommand(
                id="convert_timezone",
                title="Timezone Conversion",
                description="Convert timezone",
                handler=convert_timezone,
            ),
            PluginCommand(
                id="convert_units",
                title="Unit Conversion",
                description="Convert units",
                handler=convert_units,
            ),
        ]
