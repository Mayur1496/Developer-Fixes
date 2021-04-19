"""
Contains functions to collect fix repositories for finding patches
"""
from http_methods import make_request
from csv_processor import write_csv
from bs4 import BeautifulSoup
from solidity_parser import parser
from math import ceil
import os
import semantic_version
import git
import subprocess
import datetime
import json
import shutil
import logging

GITHUB = 'https://github.com'
HEADER = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36',
    'Cookie': '',
    "Content-Type": "text/html; charset=utf-8"}
API_HEADER = {'Accept': 'application/vnd.github.cloak-preview+json'}

fields = ['RepoName', '#Stars', '#Watchers', 'InspectionTime', 'LastActivityTime', '#ContractFiles']
repo_count = 0
start_count = 49


def clone_repo(url, path):
    """The function clones a repository locally. If already exists, reset its head to master

    :param url: GitHub URL of the repository
    :param path: Absolute path to storage location
    :return: True if cloned successfully else False
    """
    repo_name = url.split('/')[-1]
    if not os.path.exists(path + '/' + repo_name):
        try:
            git.Git(path).clone(url)
        except Exception as e:
            logging.exception(e)
            return False
    return True


def get_sol_files(path):
    """Extract list of all solidity files in a repository

    :param path: Absolute path to the repository
    :return: List of all solidity file paths
    """
    proc = subprocess.Popen(['find', path, '-type', 'f', '-name', '*.sol'], stdout=subprocess.PIPE)
    (out, _) = proc.communicate()
    all_files = out.decode("utf-8").split('\n')[:-1]
    return all_files


def check_solidity_version(url):
    """Check if a repository is a fix repository by checking if it contains atleast one file with version >=0.4.19

    :param url: URL of repository
    :return: True if repository is a fix repo else False
    """
    # clone repo
    path = os.getcwd() + '/data'
    if not os.path.exists(path):
        os.mkdir('data')

    # check if repo has .sol files or not
    response = make_request(url + '/search?q=extension%3Asol', HEADER)
    parsed = BeautifulSoup(response.content, 'html.parser')
    try:
        parsed.find('div', class_='code-list').find('a')['href']
    except Exception as e:
        logging.exception(e)
        logging.info('Does not contains .sol files')
        return False, '0'

    if not clone_repo(url, path):
        return False, '0'

    sol_files = get_sol_files(path + '/' + url.split('/')[-1])

    for sol_file in sol_files:
        try:
            parsed = parser.parse_file(sol_file)
            ver = None
            for child in parsed['children']:
                if child['type'] == 'PragmaDirective':
                    ver = child['value']
                    break
            # ver = parsed['children'][0]['value'].replace('^','')

            if not ver:
                logging.error('File version not found in file ' + str(sol_file))
                continue

            ver = ver.replace('^', '')
            if '<' in ver:
                ver = ver.split('<')[0]
            file_sol_ver = semantic_version.SimpleSpec(ver)

            # checking if version >= 0.4.19
            req_sol_ver = semantic_version.SimpleSpec('>=0.4.19')
            if req_sol_ver.match(file_sol_ver.clause.target):
                shutil.rmtree(path + '/' + url.split('/')[-1])
                return True, len(sol_files)

        except Exception as e:
            logging.exception(e)
            continue

    # delete cloned copy of repo
    shutil.rmtree(path + '/' + url.split('/')[-1])
    return False, '0'


def fetch_watchers(url):
    """Extract the number of watchers on a repository

    :param url: GitHub url of the repository
    :return: Number of watches
    """
    response = make_request(url, HEADER)
    parsed = BeautifulSoup(response.content, 'html.parser')
    watcher_count = parsed.find('a', class_='social-count').text

    watcher_count = watcher_count.split('\n')[1].strip()
    return watcher_count


def repo_details(json_response):
    """Check if repo is a fix repository, If yes, extract its metadata

    :param json_response: Parsed HTTP response of the GitHub API containing list of possible fix repos
    """
    global repo_count
    global start_count

    for item in json_response['items']:
        # for debugging...
        repo_count += 1
        print('--------------Repo Count-------------->  ' + str(repo_count))
        if repo_count < start_count:
            continue

        # ------------------------------------------------------------------------
        # Currently not in use since search only results in repos with stars >= 10

        # If stars are less than 10, then check for watchers
        # if int(item['stargazers_count']) < 10:
        #     #checking if watchers >= 10
        #     response = make_request(item['html_url'], HEADER)
        #     parsed = BeautifulSoup(response.content, 'html.parser')
        #     watcher_count = parsed.find('a', class_='social-count').text

        #     #If watcher_count is less than 10, then ignore repo
        #     if int(watcher_count) < 10:
        #         continue
        # ------------------------------------------------------------------------

        row = []
        (status, file_count) = check_solidity_version(item['html_url'])
        if status:
            # Full name of the repo
            row.append(item['full_name'])
            # Stars on the repo
            row.append(item['stargazers_count'])
            # watchers on the repo
            watchers = fetch_watchers(item['html_url'])
            row.append(watchers)
            # Inspection time
            row.append(str(datetime.datetime.now()))
            # Last update time
            row.append(item['updated_at'])
            # Count of Solidity files
            row.append(file_count)
            write_csv(os.path.dirname(os.getcwd()) + '/Repos.csv', row)
            logging.info('Repo added : ' + str(item['full_name']))


def fetch_repo_list():
    # github api request to fetch all repo with keyword:'smart contract' and stars:>9
    url = 'https://api.github.com/search/repositories?q=smart%20contract+stars:%3E9&per_page=100'

    response = make_request(url, API_HEADER)
    json_response = json.loads(response.content)

    total_repo_count = int(json_response['total_count'])
    pages = ceil(total_repo_count / 100)

    # process response from first page
    repo_details(json_response)

    # process response from rest of pages
    while pages > 1:
        try:
            nextpage_url = response.links['next']['url']
        except Exception as e:
            logging.exception(e)
            pages -= 1
            continue

        response = make_request(nextpage_url, API_HEADER)
        json_response = json.loads(response.content)
        repo_details(json_response)
        pages -= 1


def fetch_repo_details():
    # for debugging
    global repo_count
    global start_count
    start_count = 0
    repo_count = 0

    # csv file location
    path = os.path.dirname(os.getcwd())
    write_csv(path + '/Repos.csv', fields)
    fetch_repo_list()
