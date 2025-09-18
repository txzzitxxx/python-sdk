import inspect
import warnings
from collections.abc import Callable
from typing import Any, TypeVar, get_type_hints


def issue_deprecation_warning(func: Callable[..., Any], request_type: type) -> None:
    """
    Issue a deprecation warning for handlers that don't use the new request parameter style.
    """
    func_name = getattr(func, "__name__", str(func))
    warnings.warn(
        f"Handler '{func_name}' should accept a '{request_type.__name__}' parameter. "
        "Support for handlers without this parameter will be removed in a future version.",
        DeprecationWarning,
        stacklevel=4,
    )


T = TypeVar("T")
R = TypeVar("R")


def create_call_wrapper(func: Callable[..., R], request_type: type[T]) -> tuple[Callable[[T], R], bool]:
    """
    Create a wrapper function that knows how to call func with the request object.

    Returns a tuple of (wrapper_func, should_deprecate):
    - wrapper_func: A function that takes the request and calls func appropriately
    - should_deprecate: True if a deprecation warning should be issued

    The wrapper handles three calling patterns:
    1. Positional-only parameter typed as request_type (no default): func(req)
    2. Positional/keyword parameter typed as request_type (no default): func(**{param_name: req})
    3. No request parameter or parameter with default (deprecated): func()
    """
    try:
        sig = inspect.signature(func)
        type_hints = get_type_hints(func)
    except (ValueError, TypeError, NameError):
        # Can't inspect signature or resolve type hints, assume no request parameter (deprecated)
        return lambda _: func(), True

    # Check for positional-only parameter typed as request_type
    for param_name, param in sig.parameters.items():
        if param.kind == inspect.Parameter.POSITIONAL_ONLY:
            param_type = type_hints.get(param_name)
            if param_type == request_type:
                # Check if it has a default - if so, treat as old style (deprecated)
                if param.default is not inspect.Parameter.empty:
                    return lambda _: func(), True
                # Found positional-only parameter with correct type and no default
                return lambda req: func(req), False

    # Check for any positional/keyword parameter typed as request_type
    for param_name, param in sig.parameters.items():
        if param.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY):
            param_type = type_hints.get(param_name)
            if param_type == request_type:
                # Check if it has a default - if so, treat as old style (deprecated)
                if param.default is not inspect.Parameter.empty:
                    return lambda _: func(), True

                # Found keyword parameter with correct type and no default
                # Need to capture param_name in closure properly
                def make_keyword_wrapper(name: str) -> Callable[[Any], Any]:
                    return lambda req: func(**{name: req})

                return make_keyword_wrapper(param_name), False

    # No request parameter found - use old style (deprecated)
    return lambda _: func(), True
