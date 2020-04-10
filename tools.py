import pickle


def json_public_key(key, port):
    return pickle.dumps({"type": "dhkey", "data": key.decode("utf-8"), "port": port})


def json_send_message(data):
    return pickle.dumps({"type": "message", "data": data})
