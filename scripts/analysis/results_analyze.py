import json
import os
from json import load
from sys import maxsize

import psycopg2
from bs4 import BeautifulSoup


def search_empty_html(dir):
    empty, total_html, total_configs, only_empty_html = 0, 0, 0, 0
    for file in os.listdir(dir):
        total_configs += 1
        with open(os.path.join(dir, file)) as f:
            content = load(f)
            del content['ignoreList']
            only_empty = True
            for sub_conf in content.values():
                for trusted_type in sub_conf:
                    if trusted_type == 'TrustedHTML':
                        total_html += 1
                        for val in sub_conf['TrustedHTML']['scripts'].values():
                            if val:
                                only_empty = False
                                break
                        else:
                            empty += 1
                    else:
                        only_empty = False
            if only_empty:
                only_empty_html += 1
    print(f"Total amount of configs: {total_configs}")
    print(f"Total amount of HTML writing parties: {total_html}")
    print(f"Total amount of empty HTML policies: {empty}")
    print(f"Percentage of empty HTML policies: {round(empty / total_html * 100, 2)}%")
    print(f"Number of configs containing only empty HTML policies: {only_empty_html}")
    print('\n')


def collect_allowlist_lengths(dir):
    allowlisted, min, max, count, count_one = set(), maxsize, 0, 0, 0
    for file in os.listdir(dir):
        with open(os.path.join(dir, file)) as f:
            content = load(f)
            del content['ignoreList']
            for sub_conf in content.values():
                for val in sub_conf.values():
                    for directive in val:
                        if directive == 'scripts':
                            for l in val['scripts'].values():
                                res = len(l)
                                if res > 0:
                                    count += 1
                                    if res < min:
                                        min = res
                                    if res > max:
                                        max = res
                                    if res == 1:
                                        count_one += 1
                                    for elem in l:
                                        allowlisted.add(elem)
                        elif isinstance(val[directive], list) and len(val[directive]) > 0:
                            res = len(val[directive])
                            count += 1
                            if res < min:
                                min = res
                            if res > max:
                                max = res
                            if res == 1:
                                count_one += 1
                            for elem in val[directive]:
                                allowlisted.add(elem)
    print(f"Total number of non-empty allowlists: {count}")
    print(f"Total number of allowlisted values: {len(allowlisted)}")
    print(f"Minimum length of allowlist: {min}")
    print(f"Maximum length of allowlist: {max}")
    print(f"Average length of allowlist: {round(len(allowlisted) / count)}")
    print(f"Number of allowlists that contain only one element: {count_one}")
    temp1, temp2 = len(allowlisted) - count_one, count - count_one
    print(f"Average length of non-length one allowlists: {round(temp1 / temp2)}")
    print('\n')


def collect_clustering_stats(dir):
    total, only_one, more_than_one = 0, 0, 0
    for root, files, dirs in os.walk(dir):
        if files and 'regexes.json' not in files:
            total += 1
            if len(files) == 1:
                only_one += 1
            else:
                more_than_one += 1
    print(f"Total number of clusters: {total}")
    print(f"Number of clusters containing one element: {only_one}")
    print(f"Number of clusters containing more than one element: {more_than_one}")
    print('\n')


def find_json_parsable():
    total, parsable, parties = 0, 0, set()
    conn = psycopg2.connect(host="127.0.0.1", user="daniel", database="trustedtypes_20210213", password='butitwasmedio')
    cur = conn.cursor()
    cur.execute("Select distinct input_hash from tt_data where trusted_type='TrustedScript'")
    for val, in cur.fetchall():
        with open(f"/data/inputs/{val[0:2]}/{val}.txt") as file:
            content = file.read()
            total += 1
            try:
                json.loads(content[1:-1])
                parsable += 1
            except:
                continue

    print(f"Total considered inputs: {total}")
    print(f"JSON parsable inputs: {parsable}")
    print(f"Percentage: {round(parsable / total * 100, 2)}%")
    # print(f"Origin/Party combination that wrote JSON parsable stuff: {parties}")
    print('\n')


def analyze_urls():
    total, https_urls, http_urls, blob_urls, blob_http_urls, data_urls, protocol_relative, local = 0, 0, 0, 0, 0, 0, 0, 0
    conn = psycopg2.connect(host="127.0.0.1", user="daniel", database="trustedtypes_20210213", password='butitwasmedio')
    cur = conn.cursor()
    cur.execute("Select distinct input_hash from tt_data where trusted_type='TrustedScriptURL'")
    for val, in cur.fetchall():
        with open(f"/data/inputs/{val[0:2]}/{val}.txt") as file:
            content = file.read()
            total += 1
            if content.startswith('https'):
                https_urls += 1
            elif content.startswith('http'):
                http_urls += 1
            elif content.startswith('blob:'):
                blob_urls += 1
                if (content[5:]).startswith('http'):
                    blob_http_urls += 1
            elif content.startswith('data:'):
                data_urls += 1
            elif content.startswith('//'):
                protocol_relative += 1
            elif content.startswith('/') or content.startswith('.') or content.startswith('js'):
                local += 1
            else:
                print(content)

    print(f"Total number of url inputs: {total}")
    print(f"HTTPS urls: {https_urls}")
    print(f"HTTP urls: {http_urls}")
    print(f"blob urls: {blob_urls}")
    print(f"blob urls with http after it: {blob_http_urls}")
    print(f"data urls: {data_urls}")
    print(f"protocol-relative urls: {protocol_relative}")
    print(f"local urls: {local}")
    print('\n')


def search_data_frames():
    count = 0
    conn = psycopg2.connect(host="127.0.0.1", user="daniel", database="trustedtypes_20210213", password='butitwasmedio')
    cur = conn.cursor()
    cur.execute("Select distinct input_hash from tt_data where trusted_type='TrustedHTML'")
    for val, in cur.fetchall():
        with open(f"/data/inputs/{val[0:2]}/{val}.txt") as file:
            content = file.read()
            parsed = BeautifulSoup(content, "html.parser")

            for tag in parsed.find_all(True):
                if tag.name == 'iframe':
                    try:
                        if tag['src'].startswith('data:'):
                            count += 1
                    except KeyError:
                        continue
    if count == 0:
        print('No data: URL iframes found')
    else:
        print(f"Number of data: URL frames: {count}")
    print('\n')


def allow_any_search(dir):
    total, flag_set, parties, total_parties = 0, 0, set(), set()
    for file in os.listdir(dir):
        with open(os.path.join(dir, file)) as f:
            content = load(f)
            del content['ignoreList']
            for party, sub_conf in content.items():
                total_parties.add(party)
                for val in sub_conf.values():
                    for directive in val:
                        if directive == 'allow-any':
                            parties.add(party)
                            flag_set += 1
                total += 1
    print(f"Total number of sub policies: {total}")
    print(f"Number of sub policies with allow-any: {flag_set}")
    print(f"Percentage: {round(flag_set / total * 100, 2)}%")
    print(f"Amount of parties with allow-any set: {len(parties)}/{len(total_parties)}")
    print('\n')


def compare_origins():
    conn1 = psycopg2.connect(host="127.0.0.1", user="daniel", database="trustedtypes_20210213",
                             password='butitwasmedio')
    cur1 = conn1.cursor()
    conn2 = psycopg2.connect(host="127.0.0.1", user="daniel", database="trustedtypes_20210214",
                             password='butitwasmedio')
    cur2 = conn2.cursor()
    query = 'select distinct origin from tt_data;'
    cur1.execute(query)
    cur2.execute(query)
    origins1 = set(x[0] for x in cur1.fetchall())
    origins2 = set(x[0] for x in cur2.fetchall())
    print(f"Origins in one of the dbs but not the other: {(origins1 - origins2) | (origins2 - origins1)}")
    print('\n')


def get_distinct_js_count():
    conn = psycopg2.connect(host="127.0.0.1", user="daniel", database="trustedtypes_20210213", password='butitwasmedio')
    cur = conn.cursor()
    cur.execute("select distinct input_hash from tt_data where trusted_type='TrustedScript';")
    val1 = set(x[0] for x in cur.fetchall())
    cur.execute("select distinct input_hash from tt_dangerous_html;")
    val2 = set(x[0] for x in cur.fetchall())
    print(len(val1 | val2))


def analyze_sites_and_parties():
    values = set()
    origins, parties = set(), set()
    sum = 0
    with open('results.txt') as file:
        content = file.read()
    with open('functionality_results.txt') as f:
        for line in f:
            if 'Total of non-changed inputs:' in line:
                val = line.split('Total of non-changed inputs:')[1].strip()
                working, total = val.split('/')[0], val.split('/')[1]
                sum += int(total) - int(working)
            elif 'with allow-any' in line:
                break

    for line in content.split('\n'):
        origin = line.split(',')[0].split('origin:')[1].strip()
        party = line.split(',')[1].split('party:')[1].strip()
        values.add((origin, party))
        origins.add(origin)
        parties.add(party)

    print(f"Overall number of breakages: {sum}")
    print(f"Number of unique origin/party combinations: {len(values)}")
    print(f"Number of unique breaking origins: {len(origins)}")
    print(f"Number of unique breaking parties: {len(parties)}")


def main():
    config_dir = '/data/configs/'
    # search_empty_html(config_dir)
    # collect_allowlist_lengths(config_dir)
    # collect_clustering_stats('/data/outputs/')
    # find_json_parsable()
    # analyze_urls()
    # search_data_frames()
    allow_any_search('/data/allow_any_configs/')
    # compare_origins()
    # get_distinct_js_count()
    # analyze_sites_and_parties()


if __name__ == '__main__':
    main()
