const fs = require('fs');
const fetch = require('node-fetch');
const crypto = require('crypto');
const REMOTE_URL = 'https://raw.githubusercontent.com/CVEProject/cve-website/main/src/assets/data/CNAsList.json';
const LOCAL_PATH = './CNAsList.json'; // Ensure you have this file
var cnas = null;
var ch = {};
async function fetchCNAs() {
    try {
        const response = await fetch(REMOTE_URL);

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        cnas = await response.json();
        console.log('✅ Loaded CNAs from remote URL.');

    } catch (error) {
        console.warn(`❌ Remote fetch failed. Falling back to local cache: ${error.message}`);
        
        try {
            // Synchronous fallback using require() as requested
            cnas = require(LOCAL_PATH);
            console.log('✅ Loaded CNAs from local cache.');
        } catch (localError) {
            console.error(`💥 Failed to load local file: ${localError.message}`);
            cnas = {}; // Final fallback
        }
    }

    console.log(`Total CNAs loaded: ${cnas?.length || 0}`);
}

async function getFavicon(u) {
    try{
    const url='https://www.google.com/s2/favicons?sz=64&domain_url='+encodeURIComponent(u);
    const response = await fetch(url);
    if (!response.ok) throw new Error(`unexpected response ${response.statusText}`);
    var b = await response.blob();
    const arrayBuffer = await b.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    var md5 = crypto.createHash('md5').update(buffer, "binary").digest('base64');
    return(md5);
    } catch(e) {
        throw ('failed to get Favicon');
    }
}

async function generateCnaList() {
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

    var cnaList = `<html><head><title>CNA Favicons</title>
<style>
body {
    font-family: sans-serif;
    background-color: #ddd;
}
#iconlist {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(6em, 1fr));
    grid-gap: 0.5em;
}
#iconlist div {
    background-color:#fff;
    padding:0.5em;
    text-align: center;
    min-height: 4em;
    vertical-align:middle;
}
#iconlist img {
    margin: 0 auto;
    font-size: 32px;
    display: block;
    border: 1px solid #aaa;
    border-radius: 3px;
    padding:5px;
    width:32px;
    height:32px;
}
#iconlist b {
    font-weight:normal;
    margin-top:1em;
    font-size:small;
}</style>
</head><body><div id="iconlist">`;
for (c of cnas) {
    var u = new URL('https://www.cve.org/');
    try {
        var em = c.contact[0].email[0].emailAddr;
        var host= em.substr(em.indexOf('@')+1);
        u = new URL('https://www.'+host);
        console.log(u + 'got' + (await getFavicon(u)));
    } catch(er) {
        try{
            u = new URL(c.securityAdvisories.advisories[0].url);
            console.log(u + 'got' + (await getFavicon(u.protocol + '//'+ u.hostname)));
        } catch(e) {
            try{
                u = new URL(c.disclosurePolicy[0].url);
                console.log(u + 'got' + (await getFavicon(u.protocol + '//'+ u.hostname)));
            } catch(e) {
                console.log('Error:'+u);
            }
        }
    }
    var i = u.protocol + '//'+ u.hostname;

    cnaList+= `<div><img src="https://www.google.com/s2/favicons?sz=64&domain_url=${encodeURIComponent(i)}"/><b>${c.organizationName}</b></div>`
    ch[c.shortName] = {
        n: c.organizationName,
        i: i
    }
}
ch['CISA-ADP'] = {n: 'CISA ADP', i: 'https://www.cisa.gov/'};
ch['CVE'] = {n: 'CVE', i: 'https://www.cve.org/'};
ch['mitre'] = {}
return cnaList;
}

async function main(){
    await fetchCNAs();
    fs.writeFileSync('cna.html', await generateCnaList() + "</div></body></html>");
    fs.writeFileSync('cna.js', 'var cna = ' + JSON.stringify(ch));
}

main();