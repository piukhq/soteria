import logging

LOG_FORMAT = "%(asctime)s | %(levelname)8s | %(name)s\n%(message)s"


def get_logger(name: str, log_level: int = logging.DEBUG) -> logging.Logger:
    """
    Returns a correctly configured logger with the given name.
    """
    logger = logging.getLogger(name.lower().replace(" ", "-"))

    # if this logger is already configured, return it now
    if logger.handlers:
        return logger

    logger.propagate = False

    formatter = logging.Formatter(LOG_FORMAT)

    handler = logging.StreamHandler()
    handler.setLevel(log_level)
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.setLevel(log_level)

    return logger
