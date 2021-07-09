from hashlib import sha256

import psycopg2

from bs4 import BeautifulSoup
from tqdm import tqdm


def connect():
    print('Connecting to database...')
    db_user = 'daniel'
    db_pass = 'butitwasmedio'
    db_name = 'trustedtypes_20210213'
    connection = psycopg2.connect(user=db_user,
                                  password=db_pass,
                                  host="127.0.0.1",
                                  port="5432",
                                  database=db_name)
    print('Connection successfully established')
    return connection


def search_js_in_html(conn, cursor, party_origin, origin):
    cursor.execute(
        "SELECT DISTINCT input_hash, data_id FROM tt_data WHERE party_origin=%s AND trusted_type='TrustedHTML' AND origin =%s;",
        (party_origin, origin))
    values = cursor.fetchall()
    query = "INSERT INTO tt_dangerous_html(origin, party_origin, input_hash, data_id) VALUES (%s, %s, %s, %s);"
    # check = "SELECT 42 FROM tt_dangerous_html WHERE origin=%s AND party_origin=%s AND input_hash=%s;"
    for val, _id in values:
        with open(f'/data/inputs/{val[0:2]}/{val}.txt') as file:
            inp = file.read()
            if inp.startswith('http'):
                continue

            parsed = BeautifulSoup(inp, "html.parser")

            for tag in parsed.find_all(True):
                if tag.name == 'script' and tag.string:
                    # JS found!
                    # add this to avoid duplicated entries
                    # cursor.execute(check, (origin, party_origin, val))
                    # if cursor.fetchone() is None:
                    cursor.execute(query, (origin, party_origin, sha256(tag.string.encode()).hexdigest(), _id))

                for attr in tag.attrs:
                    if attr.startswith('on') and tag[attr]:
                        # JS found!
                        # cursor.execute(check, (origin, party_origin, val))
                        # if cursor.fetchone() is None:
                        cursor.execute(query, (origin, party_origin, sha256(tag[attr].encode()).hexdigest(), _id))


def main():
    conn = None
    try:
        conn = connect()
        conn.autocommit = True
        with conn.cursor() as cursor:
            cursor.execute('DROP TABLE IF EXISTS tt_dangerous_html;')
            query = "CREATE TABLE tt_dangerous_html(entry_id serial PRIMARY KEY, origin VARCHAR(500) NOT NULL, input_hash CHAR(64) NOT NULL, party_origin VARCHAR(500), data_id INTEGER NOT NULL ,CONSTRAINT dataid_constraint FOREIGN KEY(data_id) REFERENCES tt_data(data_id));"
            cursor.execute(query)
            query = "SELECT DISTINCT origin FROM tt_data LIMIT 50;"
            cursor.execute(query)
            for origin in tqdm(cursor.fetchall(), desc='Searching JS in HTML inputs per origin'):
                origin = origin[0]
                query = "SELECT DISTINCT party_origin FROM tt_data WHERE origin=%s AND trusted_type='TrustedHTML';"
                cursor.execute(query, (origin,))
                for party_origin in cursor.fetchall():
                    search_js_in_html(conn, cursor, party_origin, origin)

    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL: \n", str(error))
    finally:
        if conn is not None:
            conn.close()
    print('Connection to database successfully closed')


if __name__ == '__main__':
    main()
