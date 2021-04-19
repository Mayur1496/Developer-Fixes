from typing import Optional, Dict, Any


def get_attr(source: Optional[Dict[Any, Any]], key: Any):
    try:
        return source[key]
    except:
        return None


def remove_loc_info(d):
    if not isinstance(d, (dict, list)):
        return d
    if isinstance(d, list):
        return [remove_loc_info(v) for v in d]
    else:
        return {k: remove_loc_info(v) for k, v in d.items()
                if k not in {'loc'}}


def get_node_and_node_path(node, line):
    node_path = ['children', '[*]']  # Ignoring indices & marking them as *
    for child in node['children']:
        if child['type'] == 'ContractDefinition':
            node_path.extend(['subNodes', '[*]'])  # Ignoring indices & marking them as *
            for subNode in child['subNodes']:
                if subNode['type'] in ('StateVariableDeclaration', 'UsingForDeclaration', 'EventDefinition'):
                    if subNode['loc']['start']['line'] == line:
                        return remove_loc_info(subNode), node_path
                elif subNode['type'] in ('StructDefinition', 'EnumDefinition'):
                    for member in subNode['members']:
                        if member['loc']['start']['line'] == line:
                            node_path.extend(['member', '[*]'])
                            return remove_loc_info(member), node_path
                elif subNode['type'] in ('FunctionDefinition', 'ModifierDefinition'):
                    statements = get_attr(get_attr(subNode, 'body'), 'statements')
                    if statements:
                        for statement in statements:
                            if statement['loc']['start']['line'] == line:
                                node_path.extend(['body', 'statements', '[*]'])
                                return remove_loc_info(statement), node_path
    raise Exception('AST-Node not found')
