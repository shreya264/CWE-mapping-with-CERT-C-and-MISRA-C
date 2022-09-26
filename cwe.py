#%%
# -*- coding: utf-8 -*-
"""
1. Copy from pdf to excel
2. Read sheet1
3. Check Enforced by qac or cweccm
4. Map cwe with qac messages
"""

import pandas as pd
data = pd.read_excel("Book1.xlsx","Sheet1",engine='openpyxl')
data

d = dict()
temp = ""
temp_qac=False
cwe_rules = []
found_found_thing = False
for idx, row in data.iterrows():
  if not isinstance(row['Rule Id'],float):
    # print(row['Rule Id'])
    if 'CWE' in row['Rule Id']:
      d[row['Rule Id']] = {}
      temp = row['Rule Id']
    
    # if isinstance( row['Rule'], str) and "Enforced by" in row['Rule'] and found_found_thing == False:
    #   rules = 
  elif isinstance( row['Rule'], str) and "Enforced by" in row['Rule'] and found_found_thing == False:
    # import pdb;pdb.set_trace()
    found_thing = row['Rule'].split()[-1].split(':')[0]
    d[temp][found_thing] = list()
    found_found_thing = True
  elif isinstance( row['Rule'], str) and "Enforced by" in row['Rule'] and found_found_thing == True:
    found_thing = row['Rule'].split()[-1].split(':')[0]
    d[temp][found_thing] = list()
    found_found_thing = True
  elif found_found_thing == True:
    if isinstance(row['Rule'],float):
      found_found_thing = False
      continue
    if not isinstance(row['Rule'], int):   
        d[temp][found_thing].extend([r.strip() for r in row['Rule'].split(',') if row['Rule']!=''])  
    else:
        d[temp][found_thing].append(str(row['Rule']))
    
d
#%%

"""
1. Map misra rule to qac message
"""
import pandas as pd
data1=pd.read_excel("Book1.xlsx","Sheet2",engine='openpyxl')
data1
d1 = {}

for idx,row in data1.iterrows():
  d1[row['QAC Message']] = row['MISRA C:2012 / Coding Standard v6 Rules']
d1
#%%
"""
map cwe, qac and misra rule
d2 is used throughout from here
"""
from collections import defaultdict
d2 = defaultdict(dict)
for cwe_number, rule_dict in d.items():
  for enforced_by, listocwe in rule_dict.items():
    for cwe in listocwe:
      # if cwe and int(cwe.strip()) in d1:
        # print(int(cwe),d1[int(cwe.strip())])
        # d2[int(cwe.strip())] = d1[int(cwe.strip())]
      # print(cwe_number,enforced_by)

      if enforced_by not in d2[cwe_number]:
        d2[cwe_number][enforced_by] = {}
      if cwe and int(cwe.strip()) in d1:# and d1[int(cwe.strip())] not in d2[cwe_number][enforced_by]:
        # d2[cwe_number][enforced_by].append(d1[int(cwe.strip())])
        if int(cwe.strip()) not in d2[cwe_number][enforced_by]:
          d2[cwe_number][enforced_by][int(cwe.strip())] = []
        m_list = d1[int(cwe.strip())]
        if not isinstance(m_list,float):
        # print(m_list)
          for item in m_list.split(','):
            if item.split('\xa0')[-1] not in d2[cwe_number][enforced_by]:
              d2[cwe_number][enforced_by][int(cwe.strip())].append(item.split('\xa0')[-1])

# df = pd.DataFrame()
# for r in cwe_rules:
#   print(d2[r])
d2
#%%
"""
cert c mapping to cwe
"""
from urllib.request import urlopen
import urllib
from urllib import request
import urllib.request
from bs4 import BeautifulSoup
from lxml import html
import requests

f = ["1155"
,"1156"
,"1157"
,"1158"
,"1159"
,"1160"
,"1161"
,"1162"
,"1162"
,"1163"
,"1165"
,"1166"
,"1167"
,"1168"
,"1169"
,"1170"
,"1171"
,"1172"]



import requests
from bs4 import BeautifulSoup
from collections import defaultdict
url='https://cwe.mitre.org/data/definitions/{}.html'
result = defaultdict(list)
for i in set(f):
  # type_id = []
  table_tag =None
  temp_url=(url.format(i))
  r=requests.get(temp_url)
  soup= BeautifulSoup(r.text,'html.parser')
  div = soup.find_all('div')
  print(i)
  for x in div:
    if x.get('id') == 'Membership':
      table_tag = x
      break
  for x in table_tag.find_all('tr'):
      if 'HasMember' in str(x):
        # print(i,x.find_all('td')[0].text,x.find_all('td')[2].text)
        type_id = x.find_all('td')[2].text
        temp_url_2 = url.format(type_id)
        r2=requests.get(temp_url_2)
        soup2= BeautifulSoup(r2.text,'html.parser')
        div_2 = soup2.find_all('div')
        for y in div_2:
          if y.get('id') == 'Taxonomy_Mappings':
            table_tag_2 = y
            break
        for y in table_tag_2.find_all('tr'):
          if '-C' in str(y):
            nodeId = y.find_all('td')[1].text
            # print(i,type_id,nodeId)
            # result[f'CWE-{type_id}'].append(nodeId)
            if nodeId.strip() not in result[f'CWE-{type_id}']:
              result[f'CWE-{type_id}'].append(nodeId.strip())
#%%
"""
comment extraction from certc 
"""
import pprint
pprint.pprint(result)

import requests
from bs4 import BeautifulSoup
from collections import defaultdict
url='http://frcv002/job/VED-SourceCodeQuality/job/VED-SourceCodeQualityStrategy/job/master/lastSuccessfulBuild/artifact/build/docs/html5/internal.html#_cert_c'


results_comments= {}

r=requests.get(url)
soup= BeautifulSoup(r.text,'html.parser')
div = soup.find_all('table')


for x in div:
    if 'Table 3. Coverage of CERT C Rules' in str(x):
      table_tag = x
    #   print(table_tag)
      break
for y in table_tag.find_all('tr'):
      if '-C' in str(y):
        certc = y.find_all('td')[0].text
        comments = y.find_all('td')[5].text
        results_comments[certc]= comments
print(results_comments)
#%%

# import csv
# l = []
# l.append(['CWE_RULE','Enforced By','QAC MESSAGE','MISRA C:2012 / Coding Standard v6 Rules','CERT C','Comments'])
# with open('final_new.csv','w') as f:
#   csvwriter = csv.writer(f, delimiter=',')
#   for cwe,rule_dict in d2.items():
#     idx=0
#     comments_str = 'Not Mapped'
#     for enforced_by,rule_info in rule_dict.items():
#       if result[f'{cwe}']:
#         cert_c_rule_string = ','.join(result[f'{cwe}'])
#         certc_list = result[f'{cwe}']
#         commennts_list = []
#         for certc in certc_list:
#             if results_comments.get(certc):
#                 commennts_list.append(results_comments.get(certc,''))
#         comments_str = '|'.join(commennts_list)
#       else:
#         cert_c_rule_string = 'Not Mapped'
#       print(cert_c_rule_string)
#       if not rule_info:
#         l.append([cwe,enforced_by,None,None,cert_c_rule_string,comments_str])
#       for rule,listodir in rule_info.items():
#         # for dir in listodir:

#         if idx==0:
#           l.append([cwe,enforced_by,rule,'|'.join(listodir),cert_c_rule_string,comments_str])
#         else:
#           l.append([None,enforced_by, rule,'|'.join(listodir),None,None])
#         idx += 1

#   csvwriter.writerows(l)

#%%
"""
child parent extraction from cwe
"""
# f = ["CWE-14"
# ,"CWE-20"
# ,"CWE-120"
# ,"CWE-121"
# ,"CWE-122"
# ,"CWE-124"
# ,"CWE-125"
# ,"CWE-126"
# ,"CWE-127"
# ,"CWE-128"
# ,"CWE-129"
# ,"CWE-131"
# ,"CWE-134"
# ,"CWE-176"
# ,"CWE-188"
# ,"CWE-190"
# ,"CWE-191"
# ,"CWE-194"
# ,"CWE-195"
# ,"CWE-196"
# ,"CWE-197"
# ,"CWE-233"
# ,"CWE-234"
# ,"CWE-369"
# ,"CWE-391"
# ,"CWE-398"
# ,"CWE-456"
# ,"CWE-457"
# ,"CWE-466"
# ,"CWE-467"
# ,"CWE-468"
# ,"CWE-469"
# ,"CWE-474"
# ,"CWE-476"
# ,"CWE-478"
# ,"CWE-480"
# ,"CWE-481"
# ,"CWE-482"
# ,"CWE-483"
# ,"CWE-484"
# ,"CWE-547"
# ,"CWE-561"
# ,"CWE-562"
# ,"CWE-563"
# ,"CWE-570"
# ,"CWE-571"
# ,"CWE-587"
# ,"CWE-588"
# ,"CWE-596"
# ,"CWE-597"
# ,"CWE-628"
# ,"CWE-665"
# ,"CWE-670"
# ,"CWE-674"
# ,"CWE-681"
# ,"CWE-682"
# ,"CWE-685"
# ,"CWE-686"
# ,"CWE-697"
# ,"CWE-704"
# ,"CWE-705"
# ,"CWE-758"
# ,"CWE-768"
# ,"CWE-783"
# ,"CWE-786"
# ,"CWE-787"
# ,"CWE-788"
# ,"CWE-805"
# ,"CWE-823"
# ,"CWE-824"
# ,"CWE-835"
# ,"CWE-843"
# ,"CWE-908"
# ,"CWE-909"
# ,"CWE-136"
# ,"CWE-192"
# ,"CWE-389"
# ,"CWE-452"
# ,"CWE-465"
# ,"CWE-559"
# ,"CWE-569"
# ,"CWE-633"
# ,"CWE-735"
# ,"CWE-736"
# ,"CWE-737"
# ,"CWE-738"
# ,"CWE-739"
# ,"CWE-740"
# ,"CWE-741"
# ,"CWE-742"
# ,"CWE-743"
# ,"CWE-746"
# ,"CWE-747"
# ,"CWE-748"
# ,"CWE-680"
# ,"CWE-690"
# ,"CWE-79"
# ,"CWE-89"
# ,"CWE-123"
# ,"CWE-130"
# ,"CWE-135"
# ,"CWE-192"
# ,"CWE-416"
# ,"CWE-22"
# ,"CWE-352"
# ,"CWE-362"
# ,"CWE-364"
# ,"CWE-365"
# ,"CWE-366"
# ,"CWE-401"
# ,"CWE-415"
# ,"CWE-416"
# ,"CWE-434"
# ,"CWE-460"
# ,"CWE-462"
# ,"CWE-463"
# ,"CWE-464"
# ,"CWE-495"
# ,"CWE-496"
# ,"CWE-688"
# ,"CWE-689"
# ,"CWE-690"
# ,"CWE-733"
# ,"CWE-762"
# ,"CWE-781"
# ,"CWE-782"
# ,"CWE-785"
# ,"CWE-789"
# ,"CWE-806"
# ,"CWE-839"
# ,"CWE-910"
# ,"CWE-911"
# ,"CWE-122"
# ,"CWE-133"
# ,"CWE-134"
# ,"CWE-306"
# ,"CWE-502"
# ,"CWE-287"
# ,"CWE-798"
# ,"CWE-862"
# ,"CWE-276"
# ,"CWE-200"
# ,"CWE-522"
# ,"CWE-732"
# ,"CWE-611"
# ,"CWE-918"
# ,"CWE-77"
# ,"CWE-590"
# ,"CWE-170"
# ,"CWE-242"
# ,"CWE-363"
# ,"CWE-696"
# ,"CWE-273"
# ,"CWE-667"
# ,"CWE-252"
# ,"CWE-253"
# ,"CWE-327"
# ,"CWE-330"
# ,"CWE-338"
# ,"CWE-676"
# ,"CWE-331"
# ,"CWE-377"
# ,"CWE-456"
# ,"CWE-479"
# ,"CWE-662"
# ,"CWE-78"
# ,"CWE-88"
# ,"CWE-67"
# ,"CWE-241"
# ,"CWE-664"
# ,"CWE-404"
# ,"CWE-459"
# ,"CWE-772"
# ,"CWE-773"
# ,"CWE-775"
# ,"CWE-771"
# ,"CWE-910"
# ,"CWE-666"
# ,"CWE-672"
# ,"CWE-190"
# ,"CWE-467"
# ,"CWE-119"
# ,"CWE-704"
# ,"CWE-194"
# ,"CWE-481"]
f = list(d2.keys())


import requests
from bs4 import BeautifulSoup
url='https://cwe.mitre.org/data/definitions/{}.html'
"""
<cwe> : {
  child:[],
  parent:[]

}
"""
result_child_parent = {}
for i in set(f):
  child,parent = [],[]
  temp_url=(url.format(i.split("-")[-1]))
  r=requests.get(temp_url)
  soup= BeautifulSoup(r.text,'html.parser')
  div = soup.find_all('div')
  for x in div:
    if x.get('id') == 'Relationships':
      table_tag = x
      # print(table_tag)
      break
  for x in table_tag.find_all('tr'):
      if 'ChildOf' in str(x):
        print(x.find_all('td')[0].text,x.find_all('td')[2].text)
        child.append(x.find_all('td')[2].text)
      elif 'ParentOf' in str(x):
        # print(x)
        print(x.find_all('td')[0].text,x.find_all('td')[2].text)
        parent.append(x.find_all('td')[2].text)
  result_child_parent[i] = dict(child=set(child),parent=set(parent))

    # for row in x:
      #  war=row.find_all('td',class_='tip')
      #  print(war)

#%%
import csv
l = []
l.append(['CWE_RULE','Parentof','Childof','Enforced By','QAC MESSAGE','MISRA C:2012 / Coding Standard v6 Rules','CERT C','Comments'])
with open('final_new.csv','w') as f:
  csvwriter = csv.writer(f, delimiter=',')
  for cwe,rule_dict in d2.items():
    idx=0
    comments_str = 'Not Mapped'
    for enforced_by,rule_info in rule_dict.items():
      if result[cwe]:
        cert_c_rule_string = ','.join(result[cwe])
        certc_list = result[cwe]
        commennts_list = []
        for certc in certc_list:
            if results_comments.get(certc):
                commennts_list.append(results_comments.get(certc,''))
        comments_str = '|'.join(commennts_list)
      else:
        cert_c_rule_string = 'Not Mapped'
      if cwe in result_child_parent:
        parent = ','.join(result_child_parent[cwe].get('parent',['Not mapped']))
        child = ','.join(result_child_parent[cwe].get('child',['Not mapped']))
      print(cert_c_rule_string)
      if not rule_info:
        l.append([cwe,parent,child,enforced_by,None,None,cert_c_rule_string,comments_str])
      for rule,listodir in rule_info.items():
        # for dir in listodir:

        if idx==0:
          l.append([cwe,parent,child,enforced_by,rule,'|'.join(listodir),cert_c_rule_string,comments_str])
        else:
          l.append([None,None,None,enforced_by, rule,'|'.join(listodir),None,None])
        idx += 1


  csvwriter.writerows(l)
df = pd.DataFrame(l[1:],columns=['CWE_RULE','Parentof','Childof','Enforced By','QAC MESSAGE','MISRA C:2012 / Coding Standard v6 Rules','CERT C','Comments'])
df.to_excel('Final_cwe.xls')
# %%
