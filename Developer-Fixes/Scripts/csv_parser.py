"""
Contains functions to parse CSV files in this dataset to the set of corresponding `Record` objects
"""

from .objects import Record, Patch, Contract, Repo
from typing import Iterable, Type
import csv


def parse_csv(csvStr: str, recordCls: Type[Record]) -> Iterable[Record]:
    reader = csv.DictReader(csvStr.splitlines())
    records = tuple(recordCls.fromCSVRow(row=r, fieldname=reader.fieldnames) for r in reader)
    return records


def parse_patches_csv(csvStr: str) -> Iterable[Patch]:
    return parse_csv(csvStr, Patch)


def parse_contracts_csv(csvStr: str) -> Iterable[Contract]:
    return parse_csv(csvStr, Contract)


def parse_repos_csv(csvStr: str) -> Iterable[Repo]:
    return parse_csv(csvStr, Repo)
