import os
import constants


def parse_sql_file(path):
    with open(path, 'r') as f:
        lines = f.readlines()
    # remove comment lines
    lines = [i for i in lines if not i.startswith("--")]
    # join into one long string
    script = " ".join(lines)
    # split string into a list of commands
    commands = script.split(";")
    # ignore empty statements (like trailing newlines)
    commands = filter(lambda x: bool(x.strip()), commands)
    return commands


def exec_sql(connection, path):
    commands = parse_sql_file(path)
    for command in commands:
        connection.query(command)


def create_db(base_path):
    # make sure folder exists
    db_path = os.path.join(base_path, *constants.DBPATH)
    if not os.path.exists(db_path):
        os.makedirs(db_path)
    # make sure db exists
    full_path = os.path.join(db_path, constants.DBFILENAME)
    if not os.path.exists(full_path):
        f = open(full_path, 'a')
        f.close()


def db_setup(db, base_path):
    create_db(base_path)
    exec_sql(db, os.path.join(base_path, "sql", "create_tables.sql"))
