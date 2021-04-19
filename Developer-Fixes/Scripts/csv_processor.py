"""
Contains functions to read and write to a csv file
"""
import csv

def write_csv(filename, row):
    with open(filename, 'a') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(row)

def read_csv(filename):
    data = []
    with open(filename, 'rt') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            data.append(row)
    
    return data