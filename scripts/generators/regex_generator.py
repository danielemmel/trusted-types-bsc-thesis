import os
from hashlib import sha256
from json import dump
from re import search, escape, sub, DOTALL

from esprima import tokenize, error_handler
from js2py import eval_js

REGEX_CLASSES = [r'[a-z]', r'[a-z0-9]', r'[a-zA-Z0-9]', r'[a-zA-Z0-9\"_;-]', r'.']

if os.path.exists("/mnt/c/Users/Daniel"):
    BASE_DIR = "/mnt/c/Users/Daniel/tmp/tt/inputs"
    OUT_DIR = "/mnt/c/Users/Daniel/tmp/tt/outputs/outputs"
    ERR_DIR = "/mnt/c/Users/Daniel/tmp/tt/errors"
elif os.path.exists("/home/node-crawler"):
    BASE_DIR = "/data/inputs"
    OUT_DIR = "/data/outputs"
    ERR_DIR = "/data/errors"
else:
    print("please add your BASE_DIR")
    exit(1)

regex_js = """function evalRegex(regex, input) {
    regex = new RegExp(regex);
    return regex.test(input);
}
"""


def _verify_inputs(inputs, regex, root):
    for inp in inputs:
        check_regex = eval_js(regex_js)
        # assert check_regex(regex,
        #                   inp), f"input \n\n {inp} did not match regex \n\n {regex}\n\n comes from {root}"
        if not check_regex(regex, inp):
            with open('regexes_errors.txt', 'a') as f:
                f.write(f"input \n\n {inp} did not match regex \n\n {regex}\n\n comes from {root}")
            return False
        return True


def normalize_inputs(inps):
    # remove any kind of whitespace and comments
    normed_inps = []
    for val in (sub(r'/\*.*\*/', '', inp, flags=DOTALL) for inp in inps):
        for token in tokenize(val, options={'comment': True, 'tolerant': True}):
            if token.type == 'LineComment':
                val = val.replace(f'//{token.value}', '')
        normed_inps.append(val)
    return [sub(r'\s', '', inp) for inp in normed_inps]


def get_regex_for_tuple(values):
    # all values are equal, so just hardcode it
    if all(val == values[0] for val in values):
        return escape(values[0])
    else:
        # get input length range
        min_val, max_val = len(min(values, key=lambda x: len(x))), len(max(values, key=lambda x: len(x)))
        for res in REGEX_CLASSES:
            if min_val == max_val:
                res += '{%d}' % min_val
            else:
                res += '{%d,%d}' % (min_val, max_val)

            if all(search(f"^{res}$", inp) is not None for inp in values):
                return res


def generate_regex(inputs):
    regex = ''
    for entry in zip(*(tokenize(inp) for inp in inputs)):
        values = [token.value for token in entry]
        regex += get_regex_for_tuple(values)

    return f"^{regex}$"


def main():
    result = {}
    for root, dirs, files in os.walk(OUT_DIR):
        if len(files) >= 1:
            dir = root[:root.rfind('/')]
            if len(files) == 1:
                continue
            else:
                inputs = []
                for file in files:
                    with open(os.path.join(root, file)) as f:
                        inputs.append(f.read())
                inputs_norm = normalize_inputs(inputs)
                try:
                    regex = generate_regex(inputs_norm)
                    if _verify_inputs(inputs_norm, regex, root):
                        # all inputs in the same cluster have the same token types
                        token_string = ''.join(token.type for token in tokenize(inputs[0]))
                        token_hash = sha256(token_string.encode()).hexdigest()
                        result[dir + '/' + token_hash] = regex
                except error_handler.Error:
                    with open('errors.txt', 'a') as file:
                        file.write(f'Tokenizing error in \n{str(inputs_norm)}\nfrom path {root}\n\n')
    with open(os.path.join(OUT_DIR, 'regexes.json'), 'w') as file:
        dump(result, file, indent=4)


if __name__ == '__main__':
    main()
