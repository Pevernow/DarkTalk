import json


def json_public_key(key):
    return json.dumps({"type": "dhkey", "data": key.decode("utf-8")}).encode()


'''
def json_send_message(data):
    return json.dumps({"type": "dhkey", "data": data.decode("utf-8")}).encode()
'''
