"""
Contains functions to invoke different stages of the tool
"""
from repos import fetch_repo_details
from patches import fetch_patches_async
from contracts import fetch_contracts_async
import logging
import datetime
import os
import argparse

if __name__ == "__main__":
    # Setup logger
    logfile_path = os.path.dirname(os.getcwd()) + '/Logs'
    if not os.path.exists(logfile_path):
        os.mkdir(logfile_path)
    logging.basicConfig(filename=logfile_path + '/' + str(datetime.datetime.now()) + '.log',
                        filemode='w', level=logging.DEBUG)

    # Parse commandline arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-do", "--detector-oyente", required=True, type=str, help='Absolute Path of the oyente.py')
    parser.add_argument("-np", "--processes", type=int, help='Number of processes to execute simultaneously', default=1)
    args = parser.parse_args()

    #####################################################################
    #                   INVOKE THREE STAGES OF THE TOOL                 #
    # To aviod restart due to crashes, execute each step one at a time  #
    #####################################################################
    fetch_repo_details()
    # Pause the tool after first step and execute `python3 get_issues.py` to collect issue data
    fetch_patches_async(args.detector_oyente, args.processes)
    fetch_contracts_async(args.detector_oyente, args.processes)
