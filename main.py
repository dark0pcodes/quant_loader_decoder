"""
Quant Loader strings decoder

Runs on Python 3
"""

import re
import argparse

KEY_REGEX = '([a-fA-F\d]{32})'
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

    def get_data(self, details):
        key_index = self.binary.find(self.key[:-1])
        hex_data = self.binary[key_index - 200:key_index + 7600].split(b'\x00')
        filtered = [j for j in hex_data if j != b'' and len(j) > 2]
        result = list()

        for item in filtered:
            try:
                tmp_decoded = self.decode(item).decode(encoding='utf-8')
                if details != 'all':
                    url = re.match(URL_REGEX, tmp_decoded)

                    if url:
                        result.append(url.string)
                else:
                    result.append(tmp_decoded)
            except ValueError:
                continue

        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Quant Loader decoder")
    parser.add_argument('--file', dest="path_file", default=None, help="File to analyze", required=True)
    parser.add_argument('--details', dest="details", default='all', help="URL is to extract decode all the strings, "
                                                                         "all otherwise", required=False)
    args = parser.parse_args()

    for item in Quant(args.path_file).get_data(args.details):
        print(item)




