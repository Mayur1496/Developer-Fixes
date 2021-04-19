"""
Contains functions to perform HTTP requests
"""
import requests
from random import randint, sample
from time import sleep
import logging

def make_request(url, headers):
    """Perform HTTP request to given url

    :param url: URL
    :param headers: Custom HTTP headers
    :return: HTTP response
    """
    # wait for random time
    wait_time = randint(2, 4)
    logging.info('waiting for '+ str(wait_time) + ' seconds before next request')
    sleep(wait_time)
    response = None
    try:
        logging.info('making http request to : ' + url)
        response = requests.get(url, timeout=10, headers=headers)
        if response.status_code != 200:
            logging.error('Invalid Response for url : ' + url)
            logging.info('Retrying after 30 seconds')
            sleep(30)
            response = make_request(url, headers)
    except Exception as e:
        logging.exception(e)
        logging.info('Retrying after 20 seconds')
        sleep(20)
        response = make_request(url, headers)
    
    return response