import re

test_path = '/home/ubuntu/madagascarmods/madagascarmods-backend/tests/asaas_auth_webhook.test.js'
route_path = '/home/ubuntu/madagascarmods/madagascarmods-backend/src/routes/asaas_webhook.js'

t = open(test_path).read()
t = t.replace(
    'dbModule.query = fake.query;',
    'globalThis.__dbFake = fake.query;\n'
    'dbModule.query = fake.query;\n'
    "console.log('fake instalado:', dbModule.query === globalThis.__dbFake);",
    1,
)
open(test_path, 'w').write(t)

r = open(route_path).read()
old = "console.log('handler db === require atual?', db === require('../models/db'), '| db.query:', db.query.toString().slice(0,50));"
new = "console.log('handler: db.query === globalThis.__dbFake?', db.query === globalThis.__dbFake);"
if old in r:
    r = r.replace(old, new)
    open(route_path, 'w').write(r)
    print('route patched')
else:
    print('route already patched or not found')
