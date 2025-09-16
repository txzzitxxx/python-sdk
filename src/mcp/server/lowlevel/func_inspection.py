import inspect
import types
import warnings
from collections.abc import Callable
from typing import Any, TypeVar, Union, get_args, get_origin


def accepts_single_positional_arg(func: Callable[..., Any]) -> bool:
    """
    True if the function accepts at least one positional argument, otherwise false.

    This function intentionally does not define behavior for `func`s that
    contain more than one positional argument, or any required keyword
    arguments without defaults.
    """
    try:
        sig = inspect.signature(func)
    except (ValueError, TypeError):
        return False

    params = dict(sig.parameters.items())

    if len(params) == 0:
        # No parameters at all - can't accept single argument
        return False

    # Check if ALL remaining parameters are keyword-only
    all_keyword_only = all(param.kind == inspect.Parameter.KEYWORD_ONLY for param in params.values())

    if all_keyword_only:
        # If all params are keyword-only, check if they ALL have defaults
        # If they do, the function can be called with no arguments -> no argument
        all_have_defaults = all(param.default is not inspect.Parameter.empty for param in params.values())
        if all_have_defaults:
            return False
        # otherwise, undefined (doesn't accept a positional argument, and requires at least one keyword only)

    # Check if the ONLY parameter is **kwargs (VAR_KEYWORD)
    # A function with only **kwargs can't accept a positional argument
    if len(params) == 1:
        only_param = next(iter(params.values()))
        if only_param.kind == inspect.Parameter.VAR_KEYWORD:
            return False  # Can't pass positional argument to **kwargs

    # Has at least one positional or variadic parameter - can accept argument
    # Important note: this is designed to _not_ handle the situation where
    # there are multiple keyword only arguments with no defaults. In those
    # situations it's an invalid handler function, and will error. But it's
    # not the responsibility of this function to check the validity of a
    # callback.
    return True


def get_first_parameter_type(func: Callable[..., Any]) -> Any:
    """
    Get the type annotation of the first parameter of a function.

    Returns None if:
    - The function has no parameters
    - The first parameter has no type annotation
    - The signature cannot be inspected

    Returns the actual annotation otherwise (could be a type, Any, Union, TypeVar, etc.)
    """
    try:
        sig = inspect.signature(func)
    except (ValueError, TypeError):
        return None

    params = list(sig.parameters.values())
    if not params:
        return None

    first_param = params[0]

    # Skip *args and **kwargs
    if first_param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
        return None

    annotation = first_param.annotation
    if annotation == inspect.Parameter.empty:
        return None

    return annotation


def type_accepts_request(param_type: Any, request_type: type) -> bool:
    """
    Check if a parameter type annotation can accept the request type.

    Handles:
    - Exact type match
    - Union types (checks if request_type is in the Union)
    - TypeVars (checks if request_type matches the bound or constraints)
    - Generic types (basic support)
    - Any (always returns True)

    Returns False for None or incompatible types.
    """
    if param_type is None:
        return False

    # Check for Any type
    if param_type is Any:
        return True

    # Exact match
    if param_type == request_type:
        return True

    # Handle Union types (both typing.Union and | syntax)
    origin = get_origin(param_type)
    if origin is Union or origin is types.UnionType:
        args = get_args(param_type)
        # Check if request_type is in the Union
        for arg in args:
            if arg == request_type:
                return True
            # Recursively check each union member
            if type_accepts_request(arg, request_type):
                return True
        return False

    # Handle TypeVar
    if isinstance(param_type, TypeVar):
        # Check if request_type matches the bound
        if param_type.__bound__ is not None:
            if request_type == param_type.__bound__:
                return True
            # Check if request_type is a subclass of the bound
            try:
                if issubclass(request_type, param_type.__bound__):
                    return True
            except TypeError:
                pass

        # Check constraints
        if param_type.__constraints__:
            for constraint in param_type.__constraints__:
                if request_type == constraint:
                    return True
                try:
                    if issubclass(request_type, constraint):
                        return True
                except TypeError:
                    pass

        return False

    # For other generic types, check if request_type matches the origin
    if origin is not None:
        # Get the base generic type (e.g., list from list[str])
        return request_type == origin

    return False


def should_pass_request(func: Callable[..., Any], request_type: type) -> tuple[bool, bool]:
    """
    Determine if a request should be passed to the function based on parameter type inspection.

    Returns a tuple of (should_pass_request, should_deprecate):
    - should_pass_request: True if the request should be passed to the function
    - should_deprecate: True if a deprecation warning should be issued

    The decision logic:
    1. If the function has no parameters -> (False, True) - old style without params, deprecate
    2. If the function has parameters but can't accept positional args -> (False, False)
    3. If the first parameter type accepts the request type -> (True, False) - pass request, no deprecation
    4. If the first parameter is typed as Any -> (True, True) - pass request but deprecate (effectively untyped)
    5. If the first parameter is typed with something incompatible -> (False, True) - old style, deprecate
    6. If the first parameter is untyped but accepts positional args -> (True, True) - pass request, deprecate
    """
    can_accept_arg = accepts_single_positional_arg(func)

    if not can_accept_arg:
        # Check if it has no parameters at all (old style)
        try:
            sig = inspect.signature(func)
            if len(sig.parameters) == 0:
                # Old style handler with no parameters - don't pass request but deprecate
                return False, True
        except (ValueError, TypeError):
            pass
        # Can't accept positional arguments for other reasons
        return False, False

    param_type = get_first_parameter_type(func)

    if param_type is None:
        # Untyped parameter - this is the old style, pass request but deprecate
        return True, True

    # Check if the parameter type can accept the request
    if type_accepts_request(param_type, request_type):
        # Check if it's Any - if so, we should deprecate
        if param_type is Any:
            return True, True
        # Properly typed to accept the request - pass request, no deprecation
        return True, False

    # Parameter is typed with something incompatible - this is an old style handler expecting
    # a different signature, don't pass request, issue deprecation
    return False, True


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
