''' Utility functions, generally useful to plugins '''
import base64
from io import BytesIO


def decode_file(data):
    return BytesIO(base64.b64decode(data))
