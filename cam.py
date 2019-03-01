import subprocess
from bs4 import BeautifulSoup
import re
import csv
from itertools import zip_longest
import xlsxwriter
import sys
import os

class threat:
    def __init__(self, entity, threat, description, security, task, risk=''):
        self.entity = entity
        self.threat = threat
        self.description = description
        self.security_reqs = security
        self.tasks = task
        self.risk = risk


task = re.compile('test cases', re.IGNORECASE)
reqs = re.compile('Requirements')
page_break = re.compile('Security$')
name = re.compile('Name$')
newline = re.compile('\n')

tm_file = input('Please enter the name of the pdf file, eg. file: ELDS.pdf, enter ELDS:\n')
try:
    subprocess.run(['pdf2txt.py', '-o', 'output.html', 'files/' + tm_file + '.pdf'], check=True)
except Exception as e:
    print(e)
    print('FileNotFoundError: \nMake sure the file is in the files subdirectory(' + os.getcwd() + '/files/' + tm_file + '.pdf), and try again')
    sys.exit()
soup = BeautifulSoup(open('output.html', 'r'), 'html.parser')
#for div in soup.find_all(style=re.compile('left:53px')):
#    print(div.text)
#for div in soup.find_all(style=re.compile('left:405px')):
#    print(div.text)
#for div in soup.find_all(style=re.compile('left:125px')):
#    print(div.text)
#print(soup.find_all(style=re.compile('left:53px')))

entities = soup.find_all(style=re.compile('left:405px'))

sec_reqs_tasks = soup.find_all(style=re.compile('left:125px'))

left_list = soup.find_all(style=re.compile('left:53px'))

testo = soup.find_all(style=re.compile('left:405px|left:125px|left:53px'))

risks = soup.find_all(style=re.compile('left:230px|left:238px|left:232px'))


#for div in testo:
#    print(div.text)
#    print('---')

#for div in soup.find_all('div'):
#    print(div)
#    print('--')

breaks = []

counter = 0
for i in left_list:
    if re.match(name, i.text):
        breaks.append(counter)
    counter = counter + 1

threat_info = left_list[breaks[0]:breaks[1]]
security_info = left_list[breaks[1]:breaks[2]]
test_info = left_list[breaks[2]:]

breaks = []
counter = 0
initial_elements = soup.find_all(style=re.compile('left:53px|left:230px|left:238px|left:232px'))
for div in initial_elements:
    if re.match(name, div.text):
        breaks.append(counter)
    counter+=1
print(breaks)

risks = initial_elements[breaks[0]:breaks[1]]
for each in risks:
    print(each.text)


risk_levels = risks[breaks[0]:breaks[1]]

threats = []
info = {'threat': '', 'description': '', 'security': '', 'task': ''}
counter = 0
flag = False
sec_task_counter = 0
#left_list = soup.find_all(style=re.compile('left:53px'))[1:]
#for div in soup.find_all(style=re.compile('left:53px'))[1:]:
for div in threat_info[1:]:
    if counter == len(entities):
        break
    elif re.match(page_break, div.text):
        continue
    elif flag:
        info['description'] = div.text
        flag = False
    elif re.search(task, div.text):
        info['task'] = sec_reqs_tasks[sec_task_counter].text
        sec_task_counter = sec_task_counter + 1
        flag = False
    elif re.search(reqs, div.text):
        info['security'] = sec_reqs_tasks[sec_task_counter].text
        sec_task_counter = sec_task_counter + 1
        flag = False
    elif len(div.text) > 50:
        info['description'] = info['description'] + div.text
    else:
        if info['threat'] != '':
            threats.append(threat(entities[counter].text, info['threat'], info['description'], info['security'], info['task']))        
        info = {'threat': div.text, 'description': '', 'security': '', 'task': ''}
        counter = counter + 1
        flag = True

print(len(threats))
print(len(risk_levels))

tasks = []
security_requirements = []
for thr in threats:
    tmp = thr.security_reqs.strip().split('\n')
    security_requirements = security_requirements + tmp

    tmp = thr.tasks.strip().split('\n')
    tasks = tasks + tmp

security_requirements.sort()
security_requirements = list(set(security_requirements))

tasks.sort()
tasks = list(set(tasks))

try:
    security_requirements.remove('')
except ValueError:
    pass

try:
    tasks.remove('')
except ValueError:
    pass

curr = ''
security_dictionary = {}
for div in security_info[1:]:
    if newline.sub(' ', div.text.strip()) in security_requirements:
        security_dictionary[newline.sub(' ', div.text.strip())] = ''
        curr = newline.sub(' ', div.text.strip())
    else:
        if not curr == '':
            security_dictionary[curr] = security_dictionary[curr] + div.text

curr = ''
tasks_dictionary = {}
for div in test_info[1:]:
    if newline.sub(' ', div.text.strip()) in tasks and newline.sub(' ', div.text.strip()) not in tasks_dictionary:
        tasks_dictionary[newline.sub(' ', div.text.strip())] = ''
        curr = newline.sub(' ', div.text.strip())
    elif curr == 'skipping':
        continue
    else:
        if not curr == '':
            tasks_dictionary[curr] = tasks_dictionary[curr] + div.text

workbook = xlsxwriter.Workbook(tm_file + '_summary.xlsx')
worksheet = workbook.add_worksheet('Summary')
worksheet.write('A1', 'Threats')
worksheet.write('B1', 'Entities')
worksheet.write('C1', 'Description')
worksheet.write('D1', 'Security Requirements')
worksheet.write('E1', 'Tests')
row = 1
col = 0
for thr in threats:
    worksheet.write(row, col, thr.threat)
    worksheet.write(row, col+1, thr.entity)
    worksheet.write(row, col+2, thr.description)
    sec_reqs = thr.security_reqs.split('\n')
    test_reqs = thr.tasks.split('\n')
    for sec, task in zip_longest(sec_reqs, test_reqs, fillvalue=''):
        worksheet.write(row, col+3, sec)
        worksheet.write(row, col+4, task)
        row +=1
    row+=1

worksheet = workbook.add_worksheet('Security Requirements')
worksheet.write('A1', 'Security Requirements')
worksheet.write('B1', 'Description')
row = 1
for name, value in security_dictionary.items():
    worksheet.write(row, col, name)
    worksheet.write(row, col+1, value)
    row+=1

worksheet = workbook.add_worksheet('Test Cases')
worksheet.write('A1', 'Test Cases')
worksheet.write('B1', 'Description')
row = 1
for name, value in tasks_dictionary.items():
    worksheet.write(row, col, name)
    worksheet.write(row, col+1, value)
    row+=1


workbook.close()
