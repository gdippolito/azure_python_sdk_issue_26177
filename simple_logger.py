import logging

def get_logger(name: str):
    logger = logging.getLogger(name)

    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s [%(filename)s:%(name)s] %(message)s',
        level=logging.DEBUG,
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    return logger