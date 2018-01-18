import re

KEY_REGEX = '([a-fA-F\d]{32})'
VER_REGEX = '^(?=.+)(?:[1-9]\d*|0)?(?:\.\d+)?$'
URL_REGEX = (
    # HTTP/HTTPS.
    "(https?:\\/\\/)"
    "((["
    # IP address.
    "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
    "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
    "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
    "(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])]|"
    # Or domain name.
    "[a-zA-Z0-9\\.-]+)"
    # Optional port.
    "(\\:\\d+)?"
    # URI.
    "(/[\\(\\)a-zA-Z0-9_:%?=/\\.-]*)?"
)


class Quant(object):
    @staticmethod
    def load(filepath: str):
        with open(filepath, 'rb') as f:
            return f.read()

    def __init__(self, filepath: str):
        self.binary = self.load(filepath)
        self.key = self.get_key()[1:].encode(encoding='utf-8') + b'\x00'

    def decode(self, message: bytes):
        result = list()

        for i in range(0, len(message)):
            result.append(message[i] - self.key[i % len(self.key)])
        return bytes(result)

    def get_key(self):
        return re.findall(KEY_REGEX, self.binary.decode('latin1'))[0]

    def get_data(self):
        key_index = self.binary.find(self.key[:-1])
        hex_data = self.binary[key_index - 200:key_index + 7600].split(b'\x00')
        filtered = [j for j in hex_data if j != b'' and len(j) > 2]
        result = {
            'urls': list(),
            'ver': 'N/A'
        }

        for item in filtered:
            try:
                tmp_decoded = self.decode(item).decode(encoding='utf-8')
                url = re.match(URL_REGEX, tmp_decoded)
                ver = re.match(VER_REGEX, tmp_decoded)

                if url:
                    result['urls'].append(url.string)
                if ver:
                    result['ver'] = ver.string
            except ValueError:
                continue

        return result

a = Quant('quant_unpacked_0.exe')
test1 = a.get_data()

pass