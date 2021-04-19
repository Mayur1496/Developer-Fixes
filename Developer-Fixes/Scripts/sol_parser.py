"""
Contains methods to parse solidity files and generate information from AST nodes
"""
import subprocess
import json


def get_attr(source, key):
    try:
        return source[key]
    except:
        return None


def parse_solc(filepath):
    try:
        proc = subprocess.run(["solidity_parser", filepath], capture_output=True, text=True, check=True)
        out = proc.stdout
    except Exception as e:
        return None, e.stderr
    return json.loads(out), None


def get_node_from_line(data, lines):
    lines = lines.split(':')
    children = get_attr(data, 'children')
    if not children:
        return '', ''
    for child in children:
        start = child['loc']['start']['line']
        end = child['loc']['end']['line']
        for line in lines:
            if start <= int(line) <= end:
                for subNode in get_attr(child, 'subNodes'):
                    subNodeStart = subNode['loc']['start']['line']
                    subNodeEnd = subNode['loc']['end']['line']
                    if subNodeStart <= int(line) <= subNodeEnd:
                        return subNode['type'], subNode['name']

    return '', ''


def get_lines_from_node(data, node_type, node_name):
    lines = ''
    if not get_attr(data, 'children'):
        return lines
    for child in get_attr(data, 'children'):
        if not child.get('subNodes'):
            continue
        for subNode in get_attr(child, 'subNodes'):
            if get_attr(subNode, 'type') == node_type and get_attr(subNode, 'name') == node_name:
                subNodeStart = subNode['loc']['start']['line']
                subNodeEnd = subNode['loc']['end']['line']
                lines = ':'.join([str(line) for line in range(subNodeStart, subNodeEnd + 1)])
                return lines

    return lines


def get_oline_from_mline(targetfile, mergedfile, mlines):
    lines = ''
    # parse target file
    target_parsed, err = parse_solc(targetfile)
    if err:
        return None
    # parse merged file
    merged_parsed, err = parse_solc(mergedfile)
    if err:
        return None

    # get node info from merged file
    node_type, node_name = get_node_from_line(merged_parsed, mlines)

    if node_name:
        lines = get_lines_from_node(target_parsed, node_type, node_name)

    return lines
