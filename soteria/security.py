import json
import typing as t

from importlib import import_module

from soteria.agents import registry
from soteria.configuration import Configuration


class SecurityException(Exception):
    pass


def get_security_agent(security_type: int, *args: t.Any, **kwargs: t.Any) -> t.Any:
    """
    Retrieves an instance of a security agent. Security agents must have a file containing a class with equal names,
    where the filename is lowercase.
    :param security_type: Int. Security type choice from Configuration. e.g Configuration.RSA_SECURITY
    :param args: extra arguments to initialise security agent
    :param kwargs: extra keyword arguments to initialise security agent
    :return: agent instance
    """
    try:
        module_name, class_name = registry.TYPES[security_type].split(".")
        security_module = import_module(".agents." + module_name, package="soteria")
        agent_class = getattr(security_module, class_name)
        agent_instance = agent_class(*args, **kwargs)

    except (AttributeError, ImportError):
        error_message = "Could not find security class: {}.".format(class_name)
        raise SecurityException(error_message)

    return agent_instance


def authorise(
    handler_type: int, request: t.Any, vault_url: str, vault_token: str, config_service_url: str
) -> t.Callable:
    """
    Decorator function for validation of requests from merchant APIs. Should be used on all callback views.
    Requires scheme slug and handler type to retrieve configuration details on which security type to use.
    Scheme slug should be passed in as a parameter in the view and handler type passed in as a decorator param.
    :param handler_type: Int. should be a choice from Configuration.HANDLER_TYPE_CHOICES
    :param request: Request object. Request to authorize
    :param vault_url: Str. url of vault
    :param vault_token: Str. token to connect to vault
    :param config_service_url: Str. Url to configuration service
    :return: decorated function
    """

    def decorator(fn: t.Callable) -> t.Callable:
        def wrapper(*args: t.Any, **kwargs: t.Any) -> t.Any:
            config = Configuration(kwargs["scheme_slug"], int(handler_type), vault_url, vault_token, config_service_url)
            security_agent = get_security_agent(
                config.security_credentials["inbound"]["service"], config.security_credentials
            )
            decoded_data = json.loads(security_agent.decode(request.headers, request.get_data().decode("utf8")))

            return fn(data=decoded_data, config=config, *args, **kwargs)

        return wrapper

    return decorator
