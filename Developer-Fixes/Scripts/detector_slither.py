"""
Contains functions to run slither vulnerability detector
"""
import json
import shlex
import subprocess, shlex
import logging
import os
from typing import Optional, Dict, Any
from objects import Vulnerability
from utils import *

SLITHER_DETECTORS = 'name-reused,rtlo,shadowing-state,suicidal,uninitialized-state,uninitialized-storage,arbitrary-send,controlled-delegatecall,reentrancy-eth,incorrect-equality,locked-ether,reentrancy-no-eth,unchecked-send,reentrancy-benign,reentrancy-events'
log = logging.getLogger('slither')

def execute_slither(filepath, version, remapping):
    """Runs slither on a contract file

    :param filepath: Absolute path to contract file
    :param version: Compiler version requirement of the contract file
    :param remapping: Library remapping requirements of a contract file
    :return:
    """
    try:
        log.info(f'Executing slither on : {filepath}')
        env = { **os.environ, 'SOLC_VERSION': version }
        args = ['slither', filepath, '--json', '-', '--json-types', 'detectors', '--detect', F'{SLITHER_DETECTORS}']
        if remapping:
            args.append(F'--solc-remaps')
            args.append(F'{remapping}')
        proc = subprocess.run(args, capture_output=True, env=env, text=True)
        log.info(proc.stdout)
        log.error(proc.stderr)
        out_json = json.loads(proc.stdout)
        if not out_json['success']:
            return 'null'
    except Exception as e:
        log.error(f'Error while executing slither on {filepath}')
        log.exception(e)
        return 'null'
    return out_json

def parse_slither_output(out_json, ast, sol_file):
    detectors = get_attr(get_attr(out_json, 'results'), 'detectors')
    vulns = []
    if not detectors:
        return vulns
    for detector in detectors:
        elements = get_attr(detector, 'elements')
        if not elements:
            continue
        lines = []
        isImported = False
        for element in elements:
            if get_attr(element, 'type') == 'function':
                function_name = get_attr(element, 'name')
                contract_name = get_attr(get_attr(get_attr(element, 'type_specific_fields'), 'parent'), 'name')
            elif get_attr(element, 'type') == 'node':
                lines += get_attr(get_attr(element, 'source_mapping'), 'lines')
            file_name_used = get_attr(get_attr(element, 'source_mapping'), 'filename_used')
            if file_name_used != sol_file:
                isImported = True
                break
        if not lines or isImported:
            continue
        vuln_name = get_attr(detector, 'check')
        line_num = ':'.join(str(l) for l in lines)
        try:
            ast_node, ast_node_path = get_node_and_node_path(ast, lines[0])
        except Exception as e:
            log.exception(e)
            continue
        ast_node_path = '.'.join(ast_node_path)
        vulns.append(Vulnerability(vuln_name, sol_file, contract_name,
            function_name, line_num, ast_node_path, ast_node))
        
    return vulns
