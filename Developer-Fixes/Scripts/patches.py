"""
Contains functions to fetch patches from fix repositories
"""
import os
import logging
import datetime
import re
import csv
from pathlib import Path
import asyncio
import concurrent.futures
import git
from semantic_version import NpmSpec
from bs4 import BeautifulSoup
from typing import Dict, Iterable, Set, Tuple
from csv_processor import read_csv, write_csv
from http_methods import make_request
from detector_slither import execute_slither, parse_slither_output
from detector_oyente import execute_oyente, parse_oyente_output
from blacklist_repos import BLACKLIST_REPOS
from objects import Vulnerability, Patch
from sol_parser import parse_solc

GITHUB = 'https://github.com'
FIELDS = ['RepoName', 'PRID', 'IssueIDs', 'Commits', 'Merged', 'ContractName',
          'FunctionName', 'ContractFilePath', 'Vulnerabilities']
HEADER = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36',
          'Cookie': '',
          "Content-Type": "text/html; charset=utf-8"}
# Path to oyente.py
OYENTE_PATH = ''
# No. of processes to execute concurrently
PROCESSES = ''


def setup_logger(log_dir, filename, detector):
    # directory for detector
    cwd = os.getcwd()
    os.chdir(log_dir)
    if not os.path.exists(detector):
        os.mkdir(detector)
    os.chdir(detector)

    l = logging.getLogger(detector)
    fileHandler = logging.FileHandler(filename)
    l.setLevel(logging.DEBUG)
    l.addHandler(fileHandler)
    # reset working dir
    os.chdir(cwd)


def clone_repo(full_name, path):
    """The function clones a repository locally. If already exists, reset its head to master

    :param full_name: Full name of the repository
    :param path: Absolute path to store repository
    :return: Reference to Git repo object
    """
    if not os.path.exists(path + '/' + full_name.split('/')[1]):
        max_attempts = 10
        while max_attempts:
            try:
                git.Git(path).clone(GITHUB + '/' + full_name)
                break
            except Exception as e:
                print(e)
                max_attempts -= 1
        return git.Repo(path + '/' + full_name.split('/')[1])
    else:  # If already exists, reset HEAD to master
        repo = git.Repo(path + '/' + full_name.split('/')[1])
        repo.git.checkout('master')
        return repo


def get_commits(repo, branch):
    """Extract list of commits from a repository

    :param repo: Git object reference
    :param branch: Name of the branch for which commits are required
    :return: List of commits sorted from newest towards oldest
    """
    commits = repo.git.log('--pretty=%H', branch).split('\n')
    return commits


def get_solc_version(version_str):
    """Extract solidity version from semantic version format

    :param version_str: solidity version is the semantic version format
    :return: raw solidity version of the file
    """
    if not version_str:
        return None  # version not found in file
    version_str = ' <'.join(version_str.split('<'))
    required_version = [v for v in NpmSpec('>=0.4.19').clause.clauses]
    given_target = sorted(v.target for v in NpmSpec(version_str).clause.clauses)
    for t in given_target:
        if required_version[0].match(t):
            return str(t)
    return None  # Incompatible version


def check_lib(repo_path):
    """Check if additional library are required for contract compilation

    :param repo_path: Absolute path to repository
    """
    # check package.json
    cwd = os.getcwd()
    os.chdir(repo_path)
    if os.path.exists(f'{repo_path}/package.json'):
        if not os.path.exists(repo_path + '/node_modules'):
            # logging.info('Installing node modules for : ' + repo_path.split('/')[-1])
            os.system('npm install')

    os.chdir(cwd)


def get_sol_files(repo_path):
    sol_files = []
    for path in Path(repo_path).rglob('*.sol'):
        # remove parent directory & then skip node_modules, mock and test files
        p = path.relative_to(repo_path)
        if any(excludeDir in str(par) for par in p.parents for excludeDir in ('node_modules', 'mocks', 'test')):
            continue
        sol_files.append(str(path))
    return sol_files


def get_prid_mergestatus(full_name, commit_hash):
    """Check if a commit is merged or not. If yes, return its PRID too.

    :param full_name: Full name of the repository
    :param commit_hash: commit hash
    :return: (PRID, Merged status)
    """
    prid = None
    try:
        response = make_request(f'{GITHUB}/{full_name}/branch_commits/{commit_hash}', HEADER)
        parsed = BeautifulSoup(response.content, 'html.parser')
        prid = parsed.find('li', class_='pull-request')
        prid = prid.text.replace('(', '').replace(')', '').replace('#', '')
        return (prid, 'True')
    except:
        return ('null', 'False')


def get_issueid(issues_path, prid):
    """Extract issue IDs which contains discussion related to a PR

    :param issues_path: Path to locally extracted issues using `get_issues.py`
    :param prid: PRID
    :return: List of issue ID(s)
    """
    issue_ids = []
    if prid == 'null':
        return 'null'

    prid_ = '#' + prid
    for f in Path(issues_path).rglob('*.txt'):
        issue = open(f, 'r')
        lines = issue.readlines()
        issue_id = f.stem.split('_')[-1]
        for line in lines:
            if re.findall(prid_ + '\\D', line):
                issue_ids.append(issue_id)

    issue_ids = ';'.join(issue_ids)

    return issue_ids


def get_remappings(repo_path):
    """Extract library remapping required to compile a contract

    :param repo_path: Absolute path to repository
    :return: Space separated string of remapping
    """
    remapping = ''
    if os.path.exists(f'{repo_path}/node_modules'):
        remapping = [f'{f.name}={f.path}' for f in os.scandir(f'{repo_path}/node_modules') if
                     f.is_dir() and next(Path(f.path).rglob('*.sol'), False)]
        remapping = ' '.join(remapping)
    return remapping


def get_vulnerabilities(repo_path, sol_files):
    """Extract vulnerabilities from given list of contract files

    :param repo_path: Absolute path to repository
    :param sol_files: List of solidity files
    :return: Dictionary of Detector as key and list of corresponding vulnerabilities found as value.
    """
    global OYENTE_PATH
    vulns: Dict[str, Iterable[Vulnerability]] = {
        'slither': [],
        'oyente': []
    }

    remapping = get_remappings(repo_path)

    for sol_file in sol_files:
        # Parse solidity file
        ast, err = parse_solc(sol_file)
        if err:
            print(f'Unable to parse file {sol_file}')
            print(err)
            continue

        # get version requirement
        version_str = ''
        for child in ast['children']:
            if child['type'] == 'PragmaDirective' and child['name'] == 'solidity':
                version_str = child['value']
                break

        version = get_solc_version(version_str)
        if not version:
            break  # Skip incompitable file
        out_json = execute_slither(sol_file, version, remapping)
        if out_json != 'null':
            vulns['slither'] += parse_slither_output(out_json, ast, sol_file)

        out_json = execute_oyente(OYENTE_PATH, sol_file, version, remapping)
        if out_json != 'null':
            vulns['oyente'] += parse_oyente_output(out_json, ast, sol_file)

    return vulns


def process_repo(full_name, log_dir, data_dir, patches_csv_path, issue_dir):
    """Process a repository to find patches.

    :param full_name: Full name of the repository
    :param log_dir: Absolute path of location to write logs
    :param data_dir: Absolute path of location to store cloned repositories
    :param patches_csv_path: Absolute path of location to write results
    :param issue_dir: Absolute path of location which contains issues data
    """
    print(f'processing repo : {full_name}')

    # logfile for Slither
    slither_logfile = full_name.replace('/', '__') + '_' + str(datetime.datetime.now()) + '.log'
    setup_logger(log_dir, slither_logfile, 'slither')
    # logfile for oyente
    oyente_logfile = full_name.replace('/', '__') + '_' + str(datetime.datetime.now()) + '.log'
    setup_logger(log_dir, oyente_logfile, 'oyente')

    if not os.path.exists(data_dir + '/' + full_name.replace('/', '__')):
        os.mkdir(data_dir + '/' + full_name.replace('/', '__'))
    repo = clone_repo(full_name, data_dir + '/' + full_name.replace('/', '__'))
    repo_path = data_dir + '/' + full_name.replace('/', '__') + '/' + full_name.split('/')[1]

    # check npm/python library requirements
    check_lib(repo_path)

    # perform `git reset --hard` to revert any changes in repo
    repo.git.reset(hard=True)

    # get default branch
    default_branch = repo.git.symbolic_ref('--short', 'HEAD')

    commit_hashes = get_commits(repo, branch=default_branch)

    current_sol_files = get_sol_files(repo_path)

    # Initially add all the vulns
    vulnerabilities = get_vulnerabilities(repo_path, current_sol_files)
    # set of all vulnerabilities
    total_vuln = set(v for vulns in vulnerabilities.values() for v in vulns)

    total_commits = []
    # check for patches
    for commit_hash in commit_hashes:
        total_commits.append(commit_hash)
        sol_files = []
        # checkout commit
        repo.git.checkout(commit_hash)

        # get list of files which are changed
        files = repo.git.log('-m', '-1', '--name-only',
                             commit_hash, pretty='format:').split('\n')
        for f in files:
            if f == '':
                break
            # Keeping only .sol files
            # Ignoring mocks, tests & node_modules files
            if not f.endswith('.sol') or 'node_modules' in f or 'mocks' in f or 'test' in f:
                continue
            sol_file = repo_path + '/' + f
            # using only those files which are a part of current state of repo
            if sol_file in current_sol_files:
                sol_files.append(sol_file)

        # If no .sol files were changed
        if not sol_files:
            continue

        # dictionary of (function_name, contract_name) as Key and associated vulnerability as values
        new_vulns_slither: Dict[Tuple[str], Set[Vulnerability]] = {}
        new_vulns_oyente: Dict[Tuple[str], Set[Vulnerability]] = {}
        # set of all funtions, contract_name & file_path which containing vulnerabilities
        functions_meta = set()

        for detector, vulns in get_vulnerabilities(repo_path, sol_files).items():
            for v in vulns:
                if not v or v in total_vuln:
                    continue
                total_vuln.add(v)
                functions_meta.add((v.function_name, v.contract_name, v.contract_file_path))
                if detector == 'slither':
                    new_vulns_slither.setdefault((v.function_name, v.contract_name), set()).add(v)
                else:
                    new_vulns_oyente.setdefault((v.function_name, v.contract_name), set()).add(v)

        # If new vulnerabilities are found then add the patch to repos.csv
        if not functions_meta:
            continue
        (prid, merged_status) = get_prid_mergestatus(full_name, commit_hash)
        issues_path = issue_dir + full_name.replace('/', '__')
        issue_ids = get_issueid(issues_path, prid)
        total_commits = ';'.join(total_commits)
        for function in functions_meta:
            function_name = function[0]
            contract_name = function[1]
            # set of vulns found by slither, oyente or both
            slither_vulns = set()
            oyente_vulns = set()
            common_vulns = set()
            if (function_name, contract_name) in new_vulns_slither.keys() and (
                    function_name, contract_name) in new_vulns_oyente.keys():
                common_vulns = new_vulns_slither[(function_name, contract_name)].union(
                    new_vulns_oyente[(function_name, contract_name)])
            elif (function_name, contract_name) in new_vulns_slither.keys():
                slither_vulns = new_vulns_slither[(function_name, contract_name)]
            elif (function_name, contract_name) in new_vulns_oyente.keys():
                oyente_vulns = new_vulns_oyente[(function_name, contract_name)]

            vuln_col = []
            if common_vulns:
                vuln_col.append('Slither|Oyente:' + '|'.join(
                    f'{v.vuln_name}(' + ':'.join([str(v) for v in v.line_num]) + ')' for v in common_vulns))

            if slither_vulns:
                vuln_col.append('Slither:' + '|'.join(
                    f'{v.vuln_name}(' + ':'.join([str(v) for v in v.line_num]) + ')' for v in slither_vulns))

            if oyente_vulns:
                vuln_col.append('Oyente:' + '|'.join(
                    f'{v.vuln_name}(' + ':'.join([str(v) for v in v.line_num]) + ')' for v in oyente_vulns))
            vuln_col = ';'.join(vuln_col)

            with open(patches_csv_path, 'a') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=FIELDS)
                writer.writerow(Patch(
                    full_name,
                    prid,
                    issue_ids,
                    total_commits,
                    merged_status,
                    contract_name,
                    function_name,
                    function[2],  # contract_file_path
                    vuln_col
                ).toDictWriterRow())

        # reset total commits
        total_commits = []


async def fetch_patches():
    """This function setup loggers, reads input data from step 1, and spawns parallel processes for each repository.
    """
    repo_csv_path = os.path.dirname(os.getcwd())
    repo_data = read_csv(repo_csv_path + '/Repos.csv')

    # directory for Logs
    cwd = os.getcwd()
    os.chdir(os.path.dirname(os.getcwd()))
    log_dir = os.getcwd() + '/Logs'
    if not os.path.exists(log_dir):
        os.mkdir('Logs')
    os.chdir(log_dir)
    if not os.path.exists('Detector'):
        os.mkdir('Detector')
    log_dir = os.getcwd() + '/Detector'
    # reset working dir
    os.chdir(cwd)

    # path for patches.csv
    patches_csv_path = os.path.dirname(os.getcwd()) + '/Patches.csv'
    write_csv(patches_csv_path, FIELDS)

    # directory for storing repos
    data_dir = os.getcwd() + '/data'
    if not os.path.exists('data'):
        os.mkdir('data')

    # directory for Issue data
    issue_dir = os.path.dirname(cwd) + '/IssuesData/'

    # get list of repos which are processed already
    done_repos = {row[0] for row in read_csv(patches_csv_path)}

    # async tasks
    tasks = []
    global PROCESSES
    loop = asyncio.get_running_loop()
    with concurrent.futures.ProcessPoolExecutor(max_workers=PROCESSES) as pool:
        for row in repo_data:
            if row[0] in BLACKLIST_REPOS or row[0] in done_repos:
                continue
            tasks.append(loop.run_in_executor(pool, process_repo,
                                              row[0], log_dir, data_dir, patches_csv_path, issue_dir))

    await asyncio.wait(tasks)


def fetch_patches_async(detector_oyente: str, processes: int):
    global OYENTE_PATH
    global PROCESSES
    OYENTE_PATH = detector_oyente
    PROCESSES = processes
    asyncio.run(fetch_patches())
