"""
The file is used to collect GitHub issues data for given list of repositories
"""
from http_methods import make_request
from csv_processor import read_csv
from bs4 import BeautifulSoup
import os
import logging
from blacklist_repos import BLACKLIST_REPOS

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def get_total_pages(parsed):
    pages = 1
    try:
        pages = int(parsed.find('div', class_='paginate-container').text.split(' ')[-2])
    except:
        #If only a single page is required then 'paginate-container' is empty
        pass
    return pages

root = os.path.dirname(os.getcwd())
repo_data = read_csv(root + '/Repos.csv')

GITHUB = 'https://github.com/'
HEADER = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36',
          'Cookie': '',
          "Content-Type": "text/html; charset=utf-8"}

#setup directory for Issues data
os.chdir(root)
if not os.path.exists('IssuesData'):
    os.mkdir('IssuesData')
os.chdir('IssuesData')

for row in repo_data[1:]:
    row = row[0]
    # print('Processing  ' + row)
    repo_name = row.split('/')[1]

    #Skip blacklisted repo
    if row in BLACKLIST_REPOS:
        continue

    #store issue data in subdir named as USERNAME__REPONAME
    folder_name = row.replace('/', '__')
    if not os.path.exists(folder_name):
        os.mkdir(folder_name)

    os.chdir(folder_name)
    
    #get total number of pages
    response = make_request(GITHUB + row + '/issues?q=is%3Aissue', HEADER)
    parsed = BeautifulSoup(response.content, 'html.parser')
    pages = get_total_pages(parsed)
    
    #for each page
    #get all issues on current page
    for page in range(1, pages+1):
        response = make_request(GITHUB + row + '/issues?q=is%3Aissue&page=' + str(page), HEADER)
        parsed = BeautifulSoup(response.content, 'html.parser')
        divs = parsed.findAll('div', class_='Box-row--focus-gray')
        for div in divs:
            issue_link = div.find('a', class_='link-gray-dark').attrs['href']
            response = make_request(GITHUB + issue_link[1:], HEADER)

            #save html response of issue to reponame_issueID.html
            f = open(repo_name + '_' + issue_link.split('/')[-1] + '.html', 'w')
            f.write(response.content.decode('utf-8'))
            f.close()

            parsed = BeautifulSoup(response.content, 'html.parser')
            div = parsed.find('div', class_='js-discussion')
            text = div.text.split('\n')
            result = [x.strip() + '\n' for x in text if x.strip() != '']

            #save discussion of issue to reponame_issueID.txt
            f = open(repo_name + '_' + issue_link.split('/')[-1] + '.txt', 'w')
            f.writelines(result)
            f.close()
    
    os.chdir('..')
