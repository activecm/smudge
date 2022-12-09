"Pytest Module for Passive Data"
import pytest
import pathlib as pl
import sqlite3

from smudge import PassiveData


def test_setup_db_1():
    '''UT to ensure DB file gets created.'''
    PassiveData.setup_db()
    path = pl.Path('signature.db')
    assert path.is_file()

def test_setup_db_5():
    '''UT to ensure signatures table was created.'''
    con = sqlite3.connect('signature.db')
    cur = con.cursor()
    list_of_tables = cur.execute("""SELECT name FROM sqlite_master
            WHERE type='table'AND name='signatures'; """).fetchall()
    assert ('signatures',) in list_of_tables

def test_test_github_con_1():
    '''UT to ensure Github connection test is successful.'''
    assert PassiveData.test_github_con()
