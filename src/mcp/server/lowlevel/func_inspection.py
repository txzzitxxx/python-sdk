import inspect
from collections.abc import Callable
from typing import Any


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
