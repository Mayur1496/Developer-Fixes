"""
Contains functions to run oyente vulnerability detector
"""
import os
import subprocess
import logging
import json
import glob
from typing import Optional, Dict, Any
from pathlib import Path
from objects import Vulnerability
from utils import *

log = logging.getLogger('oyente')

def get_function_name(node, line):
    """Extract name of the function to which a line of code belongs

    :param node: AST node of the contract file
    :param line: line number
    :return: Name of the function (if found otherwise unknown)
    """
    for child in node['children']:
        start_line = child['loc']['start']['line']
        end_line = child['loc']['end']['line']
        if line >= start_line and line <= end_line:
            if not get_attr(child, 'subNodes'):
                continue
            for subNode in child['subNodes']:
                start_line_subNode = subNode['loc']['start']['line']
                end_line_subNode = subNode['loc']['end']['line']
                if subNode['type'] == 'FunctionDefinition' and line >= start_line_subNode and line <= end_line_subNode:
                    return subNode['name']

    return 'unknown'

def execute_oyente(oyente_root, filepath, version, remapping):
    """Runs oyente on a contract file

    :param oyente_root: Absolute path to oyente
    :param filepath: Absolute path to contract file
    :param version: Compiler version requirement of the contract file
    :param remapping: Library remapping requirements of a contract file
    :return: JSON containing results of oyente
    """
    try:
        log.info(f'Executing oyente on : {filepath}')
        env = { **os.environ, 'SOLC_VERSION': version }
        args = ['python3', oyente_root, '-s', filepath, '-j', '--web', '--allow-paths', os.getcwd()]
        if remapping:
            args.append(F'-rmp')
            args.append(remapping)
        proc = subprocess.run(args, capture_output=True, env=env, text=True)
        log.info(proc.stdout)
        log.error(proc.stderr)
        out_json = json.loads(proc.stdout)
    except Exception as e:
        log.error(f'Error while executing oyente on {filepath}')
        log.exception(e)
        return 'null'
    return out_json

def get_vuln_object(vuln_name, contract_file_path, contract_name, line_num, ast):
    """Create Vulnerability object for vulnerability data

    :param vuln_name: Name of vulnerability
    :param contract_file_path: Absolute path to contract file
    :param contract_name: Name of the contract
    :param line_num: Line number of the vulnerability
    :param ast: AST of the contract file
    :return: Vulnerability object
    """
    function_name = get_function_name(ast, int(line_num))
    try:
        ast_node, ast_node_path = get_node_and_node_path(ast, int(line_num))
    except Exception as e:
        log.exception(e)
        return None
    ast_node_path = '.'.join(ast_node_path)
    return Vulnerability(vuln_name, contract_file_path, contract_name, function_name,
                        line_num, ast_node_path, ast_node)

def parse_oyente_output(out_json, ast, sol_file):
    """Parse output of the Oyente JSON

    :param out_json: Output JSON from oyente
    :param ast: AST of contract file
    :param sol_file: Absolute path to contract file
    :return: List of vulnerability objects
    """
    vulnerabilities = []
    for c_filepath, f in out_json.items():
        if c_filepath != sol_file:
            continue
        for c_name, data in f.items():
            for v_name, vulns in data['vulnerabilities'].items():
                if vulns:
                    for vuln in vulns:
                        if isinstance(vuln, str):
                            line_num = vuln.split(':')[1]
                            vulnerabilities.append(
                                get_vuln_object(v_name, c_filepath, c_name,
                                line_num, ast)
                            )
                        elif isinstance(vuln, list):
                            for v in vuln:
                                line_num = v.split(':')[1]
                                vulnerabilities.append(
                                    get_vuln_object(v_name, c_filepath, c_name,
                                    line_num, ast)
                                )
    return vulnerabilities
