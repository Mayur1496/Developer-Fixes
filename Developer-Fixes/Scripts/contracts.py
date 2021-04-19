"""
Contains functions required to verify deployment address of contract files from a repository
"""
import os
import asyncio
import concurrent.futures
import logging
import subprocess
import csv
from bs4 import BeautifulSoup
from mongoengine import connect, DoesNotExist
from crytic_compile import CryticCompile, InvalidCompilation
from semantic_version import SimpleSpec, Version
from objects import DeploymentAddressDetails, Contract, Vulnerability
from http_methods import make_request
from csv_processor import read_csv, write_csv
from patches import get_sol_files, get_commits, clone_repo, get_remappings
from detector_oyente import execute_oyente, parse_oyente_output
from detector_slither import execute_slither, parse_slither_output
from sol_parser import parse_solc
from blacklist_repos import BLACKLIST_REPOS

HEADER = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36',
          'Cookie': '',
          "Content-Type": "text/html; charset=utf-8"}
FIELDS = ['RepoName', 'ContractName', 'CommitHashes', 'ContractFilePath', 'DeploymentAddress',
          'SOLC-Version', 'Vulnerabilities']
# Path to oyente.py
OYENTE_PATH = ''


def get_contract_deploymentaddr_map():
    """
    Function creates a map of contract (key) -> List of verified deployment addr(s) (value)

    The function reads a file obtained from Etherscan database which contains list of contract names
    and their deployment address.  The name of the file is expected to be 'verified-contractaddress.csv'.

    :return: Contract name (key) -> List of possible deployment addresses
  
    """
    verified_deployment_addr_path = os.path.dirname(os.getcwd()) + '/verified-contractaddress.csv'
    verified_deployment_addr = read_csv(verified_deployment_addr_path)
    contract_deploymentaddr_map = {}
    for _, ContractAddress, ContractName in verified_deployment_addr[1:]:
        contract_deploymentaddr_map.setdefault(ContractName, []).append(ContractAddress)
    return contract_deploymentaddr_map


def trim_bytecode(bytecode, compiler_version):
    """
    Function is used to remove metadata from header and trailer of the contract bytecode.

    :param bytecode: Bytecode of the contract
    :param compiler_version: Supported compiler version of the contract
    :return: Trimmed bytecode of the contract
    """
    # if compiler version >= 0.6.0
    if SimpleSpec('>=0.6.0').match(Version(compiler_version)):
        startswith = bytecode.rfind('6080604052')
        endswith = bytecode.rfind('a264697066735822')
        bytecode = bytecode[startswith:endswith]
    # if compiler version >= 0.4.22
    elif SimpleSpec('>=0.4.22').match(Version(compiler_version)):
        startswith = bytecode.rfind('6080604052')
        endswith = bytecode.rfind('a165627a7a72305820')
        bytecode = bytecode[startswith:endswith]
    # if compiler version >= 0.4.7
    elif SimpleSpec('>=0.4.7').match(Version(compiler_version)):
        startswith = bytecode.rfind('6060604052')
        bytecode = bytecode[startswith:]
    return bytecode


def get_contract_details_from_etherscan(deployment_address):
    """
    The function extract contract details of a deployed contract from the Etherscan database using its deployment address.

    :param deployment_address: deployment address of the contract
    :return: DeploymentAddressDetails object containing deployment address information
    """
    try:
        return DeploymentAddressDetails.objects(deployment_address=deployment_address).get()
    except DoesNotExist:
        # If details at deployment address does not exists
        # Fetch details from etherscan & store into local database
        url = f'https://etherscan.io/address/{deployment_address}#code'
        response = make_request(url, HEADER)
        parsed = BeautifulSoup(response.content, 'html.parser')
        _, contract_name, _, compiler_version, _, optimized, _, _ = [text for text in parsed.find('div',
                                                                                                  class_='mx-gutters-lg-1').text.split(
            '\n') if text]
        compiler_version = compiler_version[1:].split('+')[0]
        optimized, _, runs, _ = optimized.split()
        optimized = bool(optimized == 'Yes')
        verified_bytecode = parsed.find('div', id='verifiedbytecode2').text
        verified_bytecode = trim_bytecode(verified_bytecode, compiler_version)

        obj = DeploymentAddressDetails(
            deployment_address=deployment_address,
            contract_name=contract_name,
            compiler_version=compiler_version,
            optimized=optimized,
            optimized_runs=int(runs),
            blockchain_bytecode=verified_bytecode
        )
        obj.save()
        return obj


def complie_solc(source, contract_name, compiler_version, remappings='', solc_args=''):
    """Function is used to compile solidity contract and return its trimmed bytecode.

    :param source: Path to contract file
    :param contract_name: Name of the contract whose bytecode is required
    :param compiler_version: Compiler version requirement of the contract file
    :param remappings: String containing library remappings required to compile contract
    :param solc_args: String containing additional compiler argument flags
    :return: Trimmed bytecode of the contract
    """
    try:
        com = CryticCompile(source, solc_remaps=remappings, solc_solcs_select=compiler_version, solc_args=solc_args)
        return trim_bytecode(com.bytecode_runtime(contract_name), compiler_version)
    except InvalidCompilation as e:
        logging.exception(e)
        return None


def verify_contract_deployment_address(contract_name, contract_file, deployment_addresses, remappings):
    """The function is used to verify the deployment address of a contract from etherscan database.

    :param contract_name: Name of the contract
    :param contract_file: Path to contract file
    :param deployment_addresses: List of possible deployment addresses
    :param remappings: String containing library remappings required to compile contract
    :return: deployment_address: Verified deployment address of the contract if found, otherwise None
    :return: compiler_version: Compiler version of the contract obtained from etherscan
    """
    for deployment_address in deployment_addresses:
        obj = get_contract_details_from_etherscan(deployment_address)
        solc_args = ''
        if obj.optimized:
            solc_args = f'--optimize --optimize-runs {obj.optimized_runs}'
        bytecode = complie_solc(source=contract_file, contract_name=obj.contract_name, remappings=remappings,
                                compiler_version=obj.compiler_version, solc_args=solc_args)
        if bytecode == obj.blockchain_bytecode:
            return deployment_address, obj.compiler_version
    return None, None  # deployment address match not found


def process_contract(repo, full_name, repo_path, contract_file, contract_deploymentaddr_map, remappings,
                     contract_csv_path):
    """Function iterates all the commits versions of each contract and try to verify deployment address
    for each version

    :param repo: Git object reference to repository
    :param full_name: Name of the repository including user name
    :param repo_path: Absolute path of the repository
    :param contract_file: Name of the contract file
    :param contract_deploymentaddr_map: Map containing contract names and deployment addresses
    :param remappings: Library remappings
    :param contract_csv_path: Absolute path to contract csv file for writing results
    """
    global OYENTE_PATH
    # reset repo state before setching commits
    repo.git.clean('-xdf')
    repo.git.checkout('master')
    commits = get_commits(repo, contract_file)
    # Iterate each contract version by version
    # starting from latest towards oldest
    found = False
    for commit in commits:
        if found:
            return
        repo.git.clean('-xdf')
        repo.git.checkout(commit)
        parsed, err = parse_solc(contract_file)
        if err:
            logging.error(err)
            continue
        for child in parsed['children']:
            if child['type'] == 'ContractDefinition':
                contract_name = child['name']
                if contract_name not in contract_deploymentaddr_map.keys():
                    continue
                deployment_address, version = verify_contract_deployment_address(contract_name,
                                                                                 contract_file,
                                                                                 contract_deploymentaddr_map[
                                                                                     contract_name],
                                                                                 remappings)
                if deployment_address:
                    found = True
                    vuln_slither = []
                    vuln_col = []
                    out_json = execute_slither(contract_file, version, remappings)
                    if out_json != 'null':
                        vuln_slither = parse_slither_output(out_json, parsed, contract_file)
                        vuln_col.append('Slither:' + '|'.join(
                            f'{v.vuln_name}(' + ':'.join(str(v) for v in v.line_num) + ')' for v in vuln_slither))
                    vuln_oyente = []
                    out_json = execute_oyente(OYENTE_PATH, contract_file, version, remappings)
                    if out_json != 'null':
                        vuln_oyente = parse_oyente_output(out_json, parsed, contract_file)
                        vuln_col.append('Oyente:' + '|'.join(
                            f'{v.vuln_name}(' + ':'.join(str(v) for v in v.line_num) + ')' for v in vuln_oyente))

                    with open(contract_csv_path, 'a') as csvfile:
                        writer = csv.DictWriter(csvfile, fieldnames=FIELDS)
                        writer.writerow(Contract(
                            full_name,
                            contract_name,
                            commit,
                            contract_file,
                            deployment_address,
                            version,
                            ';'.join(vuln_col)
                        ).toDictWriterRow())
                    break


def process_repo_contracts(full_name, data_dir, contract_deploymentaddr_map, contract_csv_path):
    """Function tries to verify the deployment address of all the contract files in a given repository

    :param full_name: Name of the repository including user name
    :param data_dir: Absolute path to directory for cloning repository
    :param contract_deploymentaddr_map: Map containing contract names and deployment addresses
    :param contract_csv_path: Absolute path to contract csv file for writing results
    """
    repo_path = data_dir + '/' + full_name.replace('/', '__')
    repo = clone_repo(full_name, repo_path)
    repo_path += '/' + full_name.split('/')[1]

    remappings = get_remappings(repo_path)
    # get contract files
    contract_files = get_sol_files(repo_path)

    for contract_file in contract_files:
        process_contract(repo, full_name, repo_path, contract_file, contract_deploymentaddr_map, remappings,
                         contract_csv_path)


async def fetch_contracts(_OYENTE_PATH, PROCESSES):
    """Function spawns concurrent processes where each process is responsible for single repository

    :param _OYENTE_PATH: Absolute path to Oyente
    :param PROCESSES: Number of concurrent processes
    """
    global OYENTE_PATH
    OYENTE_PATH = _OYENTE_PATH
    # connect to database of deployment addresses
    connect('deployment-address-details')

    # path for Repos.csv
    repo_csv_path = os.path.dirname(os.getcwd())
    repo_data = read_csv(repo_csv_path + '/Repos.csv')

    contract_csv_path = os.path.dirname(os.getcwd()) + '/Contract.csv'
    write_csv(contract_csv_path, FIELDS)

    # directory for storing repos
    data_dir = os.getcwd() + '/data'
    if not os.path.exists('data'):
        os.mkdir('data')

    contract_deploymentaddr_map = get_contract_deploymentaddr_map()

    # async tasks
    tasks = []
    loop = asyncio.get_running_loop()
    with concurrent.futures.ProcessPoolExecutor(max_workers=PROCESSES) as pool:
        for row in repo_data[1:]:
            if row[0] in BLACKLIST_REPOS:
                continue
            tasks.append(loop.run_in_executor(pool, process_repo_contracts,
                                              row[0], data_dir, contract_deploymentaddr_map, contract_csv_path))

    await asyncio.wait(tasks)


def fetch_contracts_async(OYENTE_PATH, PROCESSES):
    asyncio.run(fetch_contracts(OYENTE_PATH, PROCESSES))
