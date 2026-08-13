route_path = '/home/ubuntu/madagascarmods/madagascarmods-backend/src/routes/asaas_webhook.js'
r = open(route_path).read()
old = "console.log('handler: db.query === globalThis.__dbFake?', db.query === globalThis.__dbFake);"
new = (
    "const cachedExports = require.cache[require.resolve('../models/db')].exports;\n"
    "    console.log('handler: cached exports.query === db.query?', cachedExports.query === db.query,\n"
    "      '| cached === db?', cachedExports === db,\n"
    "      '| cacheEntry.query:', cachedExports.query.toString().slice(0, 40),\n"
    "      '| db.query:', db.query.toString().slice(0, 40));"
)
assert old in r, 'marker not found'
r = r.replace(old, new)
open(route_path, 'w').write(r)
print('patched')
