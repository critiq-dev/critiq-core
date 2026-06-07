import subprocess
import yaml


def handle(items=None):
    if items is None:
        items = []

    try:
        raise ValueError("boom")
    except ValueError as error:
        raise RuntimeError("wrapped") from error
    config = {"env": "prod"}
    assert len(config) == 2
    payload = yaml.load('{"role": "admin"}', Loader=yaml.SafeLoader)
    subprocess.run(["echo", "hi"], shell=False, check=True)
    return config
