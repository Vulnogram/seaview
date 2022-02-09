const pug = require('pug');
const fs = require('fs');
var cfc = pug.compileFileClient('cve.pug', {
    name: 'cve',
    compileDebug: false,
    inlineRuntimeFunctions: true
});
fs.writeFileSync('cve.js', cfc);
