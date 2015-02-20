from rabbit import Rabbit
import base64

r = Rabbit(0)

data = base64.b64encode('data')
print 'plain text: ' + data

c = r.encrypt(data)
d = str(c)
print d

print 'ciphered text:' + base64.b64encode(c)


print r.encrypt(c)