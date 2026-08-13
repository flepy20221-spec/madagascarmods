test_path = '/home/ubuntu/madagascarmods/madagascarmods-backend/tests/asaas_auth_webhook.test.js'
t = open(test_path).read()
old = "console.log('handler name:', webhookHandler.name);"
new = "console.log('handler src head:', webhookHandler.toString().slice(0, 80));"
assert old in t, 'marker not found'
t = t.replace(old, new, 1)
open(test_path, 'w').write(t)
print('patched')
