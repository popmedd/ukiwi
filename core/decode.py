import base64
from urllib.parse import quote, unquote, urlencode
import re
def decode(argument,decode_list):
    for decode_type in decode_list:
        if decode_type == "url":
            argument = str(unquote(argument))
        elif decode_type == "base":
            base_str = re.search(r'([a-zA-Z0-9+/]{40,}={2})|^([a-zA-Z0-9+/]{40,}={1})|^([a-zA-Z0-9+/]{40,})', argument,re.S).group()
            argument = str(base64.b64decode(base_str))
    return argument