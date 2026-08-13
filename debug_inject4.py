import re

route_path = '/home/ubuntu/madagascarmods/madagascarmods-backend/src/routes/asaas_webhook.js'
test_path = '/home/ubuntu/madagascarmods/madagascarmods-backend/tests/asaas_auth_webhook.test.js'

# 1. Remover todo o debug do asaas_webhook.js (deixa apenas a linha de forceFake se desejado)
r = open(route_path).read()
# remover bloco de debug grande
debug_block = """    const cachedExports = require.cache[require.resolve('../models/db')].exports;
    console.log('handler: cached exports.query === db.query?', cachedExports.query === db.query,
      '| cached === db?', cachedExports === db,
      '| cacheEntry.query:', cachedExports.query.toString().slice(0, 40),
      '| db.query:', db.query.toString().slice(0, 40));
"""
r = r.replace(debug_block, "")
# remover a linha forceFake solta anterior se houver
r = re.sub(r"^    if \(globalThis\.__forceFake\) db\.query = globalThis\.__forceFake;\n", "", r, flags=re.M)
open(route_path, 'w').write(r)

# 2. Restaurar o teste removendo logs de debug e o wrapping quebrado
t = open(test_path).read()
t = t.replace("globalThis.__dbFake = fake.query;\n", "")
t = re.sub(r"^console\.log\('fake instalado.*\n", "", t, flags=re.M)
t = re.sub(r"^console\.log\('db keys.*\n", "", t, flags=re.M)
t = re.sub(r"^console\.log\('layers.*\n", "", t, flags=re.M)
t = t.replace("console.log('handler src head:', webhookHandler.toString().slice(0, 80));", "")
t = t.replace(
    "function call(body, headers) {\n  if (globalThis.__forceFake === undefined) globalThis.__forceFake = fake.query;\n  return (async () => {",
    "async function call(body, headers) {"
)
t = t.replace(
    """  const { req, res, get } = makeReqRes(body, headers);
  await webhookHandler(req, res);
  return get();
}
  })();
}""",
    """  const { req, res, get } = makeReqRes(body, headers);
  await webhookHandler(req, res);
  return get();
}"""
)
open(test_path, 'w').write(t)
print('cleaned')
