const fs = require('fs');
const path = require('path');

(async () => {
  let failed = 0;
  const files = fs.readdirSync(__dirname).filter(f => f.endsWith('.test.js')).sort();
  for (const f of files) {
    try {
      await require(path.join(__dirname, f))();
      console.log('ok   ', f);
    } catch (e) {
      failed++;
      console.error('FAIL ', f, '\n', e.stack);
    }
  }
  process.exit(failed ? 1 : 0);
})();
