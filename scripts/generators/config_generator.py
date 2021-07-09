import argparse
import json
from base64 import b64decode
from hashlib import sha256
from sys import stderr
from urllib.parse import urlparse

import psycopg2
from bs4 import BeautifulSoup
from esprima import tokenize, error_handler
from tqdm import tqdm


def positive_int(value):
    try:
        value = int(value)
        if value <= 0:
            raise argparse.ArgumentTypeError(f"Non-positive value {value} given as parameter")
    except ValueError:
        raise argparse.ArgumentTypeError(f"Non-number value {value} given as parameter")
    return value


def json_path(path):
    with open(path) as f:
        try:
            json.load(f)
            return path
        except Exception:
            raise argparse.ArgumentTypeError(f"Given path {path} does not lead to valid JSON file")


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--credentials', default='/data/credentials.json',
                        help='Path to JSON file containing the basic database credentials')
    parser.add_argument('-l', '--logfile', default=None,
                        help='Path to file for logging output')
    parser.add_argument('-db', '--databases', nargs='*',
                        help='Names of the databases to be used')
    parser.add_argument('-t', '--threshold', default=1000, type=positive_int,
                        help='Number of required allowlist entries above which a party is allowed to write any input for that Trusted Type')
    parser.add_argument('-r', '--regexes', default='/data/outputs/regexes.json', type=json_path,
                        help='Path to JSON file containing regexes used in the generation')
    parser.add_argument('-p', '--processes', default=100, type=positive_int,
                        help='Number of processes to be used in the generation')
    args = parser.parse_args()

    return vars(args)


def print_warning(warning, logfile=None):
    warning_str = f"WARNING: {warning}\n"
    if logfile is not None:
        with open(logfile, 'a') as file:
            file.write(warning_str)
    else:
        print(warning_str, file=stderr)


def _merge_configs(old_config, new_config):
    for key in new_config:
        # add key and its value to original dict
        if key not in old_config:
            old_config[key] = new_config[key]
        # update value to concatenation of both lists
        elif isinstance(old_config[key], list):
            old_config[key] = old_config[key] + new_config[key]
        # update flag value to OR of both values
        elif isinstance(old_config[key], bool):
            old_config[key] = old_config[key] | new_config[key]
        else:
            _merge_configs(old_config[key], new_config[key])


def _get_config_html(conn, cursor, party_origin, origin, logfile, threshold, regex_path):
    cursor.execute(
        "SELECT DISTINCT input_hash FROM tt_data WHERE party_origin=%s AND trusted_type='TrustedHTML' AND origin =%s;",
        (party_origin, origin))
    values = cursor.fetchall()
    regexes = set()
    script_hashes = set()
    prefixes = set()
    for val, in values:
        with open(f'/data/inputs/{val[0:2]}/{val}.txt') as file:
            inp = file.read()

        if inp.startswith('http'):
            print_warning(
                f"URL-like input {inp} found, written by party_origin {party_origin} to origin {origin}, "
                f"skipping this input", logfile)
            continue

        parsed = BeautifulSoup(inp, "html.parser")

        for tag in parsed.find_all(True):
            if tag.name == 'script':
                # allowlist prefixes of external scripts
                if 'src' in tag.attrs and tag['src']:
                    try:
                        url = urlparse(tag['src'].strip())
                    except Exception as err:
                        with open('config_errors.txt', 'a') as f:
                            f.write(f"Exception {err} occured from input\n{tag['src']}")
                            continue
                    if not url.scheme:
                        if not url.netloc and url.path:
                            prefixes.add(url.path)
                        elif url.netloc:
                            val = f"//{url.netloc}{url.path}"
                            prefixes.add(val)
                    else:
                        val = f"{url.scheme}://{url.netloc}{url.path}"
                        prefixes.add(val)
                # allowlist inline scripts
                elif tag.string:
                    try:
                        token_string = ''.join(token.type for token in tokenize(tag.string))
                        token_hash = sha256(token_string.encode()).hexdigest()
                    except error_handler.Error:
                        with open('config_errors.txt', 'a') as f:
                            f.write(f"Couldn't tokenize input {tag.string}\n")
                            script_hashes.add(sha256(tag.string.encode()).hexdigest())
                            continue

                    origin = origin if origin != 'null' else '//null'
                    party_origin = party_origin if party_origin != 'null' else '//null'
                    cluster = f"/data/outputs/{origin.split('/')[2]}/{party_origin.split('/')[2]}/{token_hash}"
                    with open(regex_path) as file:
                        content = json.load(file)
                        try:
                            regexes.add(content[cluster])
                        except KeyError:
                            script_hashes.add(sha256(tag.string.encode()).hexdigest())

            # allowlist event handlers
            for attr in tag.attrs:
                if attr.startswith('on') and tag[attr]:
                    try:
                        token_string = ''.join(token.type for token in tokenize(tag[attr]))
                        token_hash = sha256(token_string.encode()).hexdigest()
                    except error_handler.Error:
                        with open('config_errors.txt', 'a') as f:
                            f.write(f"Couldn't tokenize input {tag[attr]}\n")
                            script_hashes.add(sha256(tag[attr].encode()).hexdigest())
                            continue

                    origin = origin if origin != 'null' else '//null'
                    party_origin = party_origin if party_origin != 'null' else '//null'
                    cluster = f"/data/outputs/{origin.split('/')[2]}/{party_origin.split('/')[2]}/{token_hash}"
                    with open(regex_path) as file:
                        content = json.load(file)
                        try:
                            regexes.add(content[cluster])
                        except KeyError:
                            script_hashes.add(sha256(tag[attr].encode()).hexdigest())

    if len(regexes) + len(prefixes) + len(script_hashes) > threshold:
        return {'TrustedHTML': {
            'scripts': {
                'regexes': [],
                'prefixes': [],
                'hashes': []
            },
            "strict": False,
            "allow-any": True}
        }
    else:
        return {'TrustedHTML': {
            'scripts': {
                'regexes': list(regexes),
                'prefixes': list(prefixes),
                'hashes': list(script_hashes)
            },
            "strict": False}
        }


def _get_config_script(conn, cursor, party_origin, origin, logfile, threshold, regex_path):
    cursor.execute(
        "SELECT DISTINCT input_hash FROM tt_data WHERE party_origin=%s AND trusted_type='TrustedScript' AND origin =%s;",
        (party_origin, origin))
    regexes = set()
    hashes = set()
    values = cursor.fetchall()
    for val, in values:
        with open(f"/data/inputs/{val[0:2]}/{val}.txt") as file:
            inp = file.read()
        try:
            token_string = ''.join(token.type for token in tokenize(inp))
            token_hash = sha256(token_string.encode()).hexdigest()
        except error_handler.Error:
            with open('config_errors.txt', 'a') as f:
                f.write(f"Couldn't tokenize input {inp}\n")
                hashes.add(val)
                continue

        origin = origin if origin != 'null' else '//null'
        party_origin = party_origin if party_origin != 'null' else '//null'
        cluster = f"/data/outputs/{origin.split('/')[2]}/{party_origin.split('/')[2]}/{token_hash}"
        with open(regex_path) as file:
            content = json.load(file)
            try:
                regexes.add(content[cluster])
            except KeyError:
                hashes.add(val)

    if len(regexes) + len(hashes) > threshold:
        return {
            'TrustedScript': {'regexes': [], 'hashes': [], 'allow-any': True}}
    else:
        return {'TrustedScript': {'regexes': list(regexes), 'hashes': list(hashes)}}


def _get_config_script_url(conn, cursor, party_origin, origin, logfile, threshold, regex_path):
    cursor.execute(
        "SELECT DISTINCT input_hash FROM tt_data WHERE party_origin=%s AND trusted_type='TrustedScriptURL' AND origin =%s;",
        (party_origin, origin))

    data_hashes = set()
    prefixes = set()
    values = cursor.fetchall()
    for val, in values:
        with open(f'/data/inputs/{val[0:2]}/{val}.txt') as file:
            url = file.read().strip()

            if url.startswith('data:'):
                seperator_index = url.find(',')
                prefix = url[:seperator_index]
                data = url[seperator_index + 1:]
                if 'base64' in prefix:
                    data = b64decode(data).decode()
                # get hash of data URLs' content
                hasher = sha256()
                hasher.update(data.encode())
                val = hasher.hexdigest()
                data_hashes.add(val)
                continue

            if url.startswith('blob:'):
                url = url[5:]

            # allowlist URLs pointing to local resources without potential GET params
            try:
                url = urlparse(url)
            except Exception as err:
                with open('config_errors.txt', 'a') as f:
                    f.write(f"Exception {err} occured from input\n{url}")
                    continue
            if not url.scheme:
                if not url.netloc and url.path:
                    prefixes.add(url.path)
                elif url.netloc:
                    val = f"//{url.netloc}{url.path}"
                    prefixes.add(val)
            else:
                val = f"{url.scheme}://{url.netloc}{url.path}"
                prefixes.add(val)

    if len(data_hashes) + len(prefixes) > threshold:
        return {'TrustedScriptURL': {'dataHashes': [], 'prefixes': [], 'allow-any': True}}
    else:
        return {'TrustedScriptURL': {'dataHashes': list(data_hashes), 'prefixes': list(prefixes)}}


types_dict = {'TrustedHTML': _get_config_html, 'TrustedScript': _get_config_script,
              'TrustedScriptURL': _get_config_script_url}


def _connect(credentials_path, names=None):
    print('Connecting to database...')
    with open(credentials_path) as file:
        credentials = json.load(file)
        user, passw, name, host, port = credentials.values()
    if names is not None:
        for name in names:
            print('Connection successfully established')
            yield psycopg2.connect(user=user, password=passw, host=host, port=port,
                                   database=name), user, passw, name, host, port
    else:
        connection = psycopg2.connect(user=user, password=passw, host=host, port=port, database=name)
        print('Connection successfully established')
        yield connection, user, passw, name, host, port


def synthesize_configs(origin, configs, args, user, passw, name, host, port):
    conn = None
    try:
        conn = psycopg2.connect(user=user, password=passw, host=host, port=port, database=name)
        with conn.cursor() as cursor:
            config = {}
            # this one has way too many entries
            if 'worldmeters.info' in origin:
                return
            query = "SELECT DISTINCT party_origin, ARRAY_AGG(trusted_type) FROM (SELECT DISTINCT party_origin, trusted_type FROM tt_data WHERE origin=%s) AS foo GROUP BY party_origin;"
            cursor.execute(query, (origin,))
            for party_origin, types_array in cursor.fetchall():
                tt_dict = {}
                for _type in types_array:
                    tt_dict.update(
                        types_dict[_type](conn, cursor, party_origin, origin, args['logfile'], args['threshold'],
                                          args['regexes']))

                config.update({party_origin: tt_dict})
            config.update({'ignoreList': []})
            if origin not in configs:
                configs[origin] = config
            else:
                _merge_configs(configs[origin], config)

    except psycopg2.Error as error:
        print("Error while connecting to PostgreSQL: \n", str(error))


def init_generation(args):
    # manager = Manager()
    # configs = manager.dict()
    configs = {}
    conn = None
    try:
        for conn, user, passw, name, host, port in _connect(args['credentials'], args['databases']):
            with conn.cursor() as cursor:
                query = "SELECT DISTINCT origin FROM tt_data;"
                cursor.execute(query)
                origins = [(origin[0], configs, args, user, passw, name, host, port)
                           for origin in cursor.fetchall()]
            # with Pool(args['processes']) as pool:
            #    pool.starmap(synthesize_configs, origins)
            for origin in tqdm(origins, desc='Generating configs'):
                synthesize_configs(*origin)
        return configs
    except psycopg2.Error as error:
        print("Error while connecting to PostgreSQL: \n", str(error))
    finally:
        if conn is not None:
            conn.close()
        print('Connection to database successfully closed')


def main():
    configs_map = init_generation(get_args())
    for origin, data in configs_map.items():
        if origin != 'null':
            origin = (urlparse(origin)).netloc
        with open(f'/data/configs/{origin}_config.json', 'w') as f:
            json.dump(data, f, indent=4)


if __name__ == '__main__':
    main()
