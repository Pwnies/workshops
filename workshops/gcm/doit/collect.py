import requests

target = 'rot256.io:8080'
target = 'http://localhost:5000'

def sample():
    ses = requests.Session()
    ses.get(target)
    return ses.cookies['auth']

s1 = sample()
s2 = sample()

with open('sample1.tmp', 'w') as f:
    f.write(s1)

with open('sample2.tmp', 'w') as f:
    f.write(s2)
