"""
Python object corresponds to each record in our CSV files in this dataset

Requires Python >= 3.7
"""

from pathlib import Path
from typing import Dict, Optional, Iterable, Tuple, Mapping, Any, Type, ClassVar
import attr
from abc import ABC, abstractmethod
from csv import DictReader, DictWriter
from datetime import datetime
import re
import json
from deepdiff import DeepDiff
from mongoengine import Document, StringField, IntField, BooleanField

def convert_if_type_mismatch(self, attrib, val):
    return val if isinstance(val, attrib.type) else attr.setters.convert(self, attrib, val)

attr_on_setattr_convert_if_type_mismatch = [convert_if_type_mismatch, attr.setters.validate]

def convert_vuln(value):
    return { tuple(detectors.split('|')) : tuple( v+')' for v in re.split('\)\|*', vuls) if v) for detectors, vuls in (x.split(':', maxsplit=1) for x in value.split(';')) }


@attr.s(auto_attribs=True, init=False)
class Record(ABC):
    # Note: following intentioanlly unmodifiable when instantiating
    _CUSTOM_CSV_FIELD_NAMES_MAP: ClassVar[Dict[str, str]] = {} # From class attribute name to specific CSV field name
    
    # From CSV field name to class attribute name. By default, they are assumed to be the same unless specified by `self._CUSTOM_CSV_FIELD_NAMES_MAP`
    __CSV_FIELD_NAMES_MAP: ClassVar[Optional[Dict[str, str]]] = None # Note: this is a cache object, access with `_get_csv_field_map` instead
    
    @classmethod
    def _get_csv_field_map(selfCls) -> Dict[str, str]:
        
        if selfCls.__CSV_FIELD_NAMES_MAP is None:
            selfClsFields = tuple(attr.fields_dict(selfCls).keys())
            assert all(f in selfClsFields for f in selfCls._CUSTOM_CSV_FIELD_NAMES_MAP.keys() ), '_CUSTOM_CSV_FIELD_NAMES_MAP has unknown keys!'
            selfCls.__CSV_FIELD_NAMES_MAP = { **{ f: f for f in selfClsFields },
                                             **{ csv_field: cls_field for cls_field, csv_field in selfCls._CUSTOM_CSV_FIELD_NAMES_MAP.items() } }
        return selfCls.__CSV_FIELD_NAMES_MAP
    
    @abstractmethod
    # Return type to match with `csv._DictRow` (unable to import this type though)
    def toDictWriterRow(self) -> Mapping[str, Any]:
        """
        Return a row object for `csv.DictWriter` to write to CSV files
        """
        pass
    
    @classmethod
    def fromCSVRow(selfCls: Type["Record"], row: Mapping[str, str], fieldname: Optional[Iterable[str]]=None) -> "Record":
        """
        Convert the raw csv string for one row into the corresponding Record object
        """
        
        csv_field_map = selfCls._get_csv_field_map()
        
        if fieldname is None:
            fieldname = tuple(csv_field_map.keys())

        return selfCls(**{csv_field_map[csv_field]: val for csv_field, val in row.items()})

    
@attr.s(auto_attribs=True, on_setattr=attr_on_setattr_convert_if_type_mismatch)
class Patch(Record):
    RepoName: str
    PRID: Optional[int] = attr.ib(converter=lambda x: None if x == 'null' else int(x))
    IssueIDs: Optional[Iterable[int]] = attr.ib(converter=lambda x: tuple(int(y) for y in x.split(';') if y) if x!='null' else None)
    Commits: Iterable[str] = attr.ib(converter=lambda x: tuple(y for y in x.split(';')))
    Merged: bool = attr.ib(converter=bool)
    ContractName: str
    FunctionName: str # Empty string for default function, "constructor" for constructor function
    ContractFilePath: Path = attr.ib(converter=Path)
    Vulnerabilities: Dict[Tuple[str], Iterable[str]] = attr.ib(converter=convert_vuln)
    
    # TODO
    def toDictWriterRow(self):
        row = {}
        row['RepoName'] = self.RepoName 
        row['PRID'] = str(self.PRID) if self.PRID is not None else 'null'
        row['IssueIDs'] = ';'.join(str(IssueId) for IssueId in self.IssueIDs) if self.IssueIDs else 'null'
        row['Commits'] = ';'.join(commit for commit in self.Commits)
        row['Merged'] = str(self.Merged)
        row['ContractName'] = self.ContractName
        row['FunctionName'] = self.FunctionName
        row['ContractFilePath'] = str(self.ContractFilePath)
        row['Vulnerabilities'] = ';'.join(F'{"|".join(detector)}:{"|".join(vuls)}' for detector, vuls in self.Vulnerabilities.items())

        return row


@attr.s(auto_attribs=True, on_setattr=attr_on_setattr_convert_if_type_mismatch)
class Contract(Record):
    _CUSTOM_CSV_FIELD_NAMES_MAP: ClassVar[Dict[str, str]] = { 
        'SOLC_Version': 'SOLC-Version',
    }
                                          
    RepoName: str
    ContractName: str
    CommitHashes: Iterable[str] = attr.ib(converter=lambda x: tuple(y for y in x.split(';')))
    ContractFilePath: Path = attr.ib(converter=Path)
    DeploymentAddress: str
    SOLC_Version: Iterable[str] = attr.ib(converter=lambda x: tuple(y for y in x.split(';')))
    Vulnerabilities: Dict[Tuple[str], Iterable[str]] = attr.ib(converter=convert_vuln)
    # TODO
    def toDictWriterRow(self):
        row = {}
        row['RepoName'] = self.RepoName
        row['ContractName'] = self.ContractName
        row['CommitHashes'] = ';'.join(CommitHash for CommitHash in self.CommitHashes)
        row['ContractFilePath'] = str(self.ContractFilePath)
        row['DeploymentAddress'] = self.DeploymentAddress
        row['SOLC-Version'] = ';'.join(version for version in self.SOLC_Version)
        row['Vulnerabilities'] = ';'.join(F'{"|".join(detector)}:{"|".join(vuls)}' for detector, vuls in self.Vulnerabilities.items())

        return row

                                          
@attr.s(auto_attribs=True, on_setattr=attr_on_setattr_convert_if_type_mismatch)
class Repo(Record):
    _CUSTOM_CSV_FIELD_NAMES_MAP: ClassVar[Dict[str, str]] = { 
        'Stars': '#Stars',
        'Watchers': '#Watchers',
        'ContractFiles': '#ContractFiles',
    }

    RepoName: str
    Stars: int = attr.ib(converter=int)
    Watchers: int = attr.ib(converter=int)
    InspectionTime: datetime = attr.ib(converter=lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S.%f'))
    LastActivityTime: datetime = attr.ib(converter=lambda x: datetime.strptime(x, '%Y-%m-%dT%H:%M:%SZ'))
    ContractFiles: int = attr.ib(converter=int)

    def toDictWriterRow(self):
        row = {}
        row['RepoName'] = self.RepoName
        row['#Stars'] = str(self.Stars)
        row['#Watchers'] = str(self.Watchers)
        row['InspectionTime'] = str(self.InspectionTime)
        row['LastActivityTime'] = str(self.LastActivityTime)
        row['#ContractFiles'] = str(self.ContractFiles)

        return row

@attr.s(auto_attribs=True, hash=False, eq=False)
class Vulnerability:
    vuln_name: str
    contract_file_path: Path = attr.ib(converter=Path)
    contract_name: str
    function_name: str
    line_num: Iterable[int] = attr.ib(converter=lambda x: tuple(int(y) for y in x.split(':')))
    ast_node_path: str
    ast_node: Dict[str, Any]

    def __eq__(self, other):
        return (self.ast_node_path == other.ast_node_path and
                not DeepDiff(self.ast_node, other.ast_node, ignore_order=True) and
                self.contract_name == other.contract_name and
                self.function_name == other.function_name and
                self.vuln_name == other.vuln_name)

    def __hash__(self):
        return (hash(self.ast_node_path) ^
                hash(json.dumps(self.ast_node, sort_keys=True)) ^
                hash(self.contract_name) ^
                hash(self.function_name) ^
                hash(self.vuln_name))

class DeploymentAddressDetails(Document):
    deployment_address = StringField(required=True, unique=True)
    contract_name = StringField(required=True)
    compiler_version = StringField(required=True)
    optimized = BooleanField(required=True)
    optimized_runs = IntField(default=0)
    blockchain_bytecode = StringField(required=True)
