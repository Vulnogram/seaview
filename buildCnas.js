const fs = require('fs');
const fetch = require('node-fetch');
const crypto = require('crypto');
const REMOTE_URL = 'https://raw.githubusercontent.com/CVEProject/cve-website/main/src/assets/data/CNAsList.json';
const LOCAL_PATH = './CNAsList.json'; // Ensure you have this file
const BATCH_SIZE = 5;
const BATCH_DELAY_MS = 300;
const GENERIC_FAVICON_MD5 = '81addaa406504038756c8f1613668203';

function saveFavicon(shortName, buffer, md5) {
    if (md5 === GENERIC_FAVICON_MD5 && !shortName.includes('github')) return false;
    fs.writeFileSync(`./icons/${shortName}.png`, buffer);
    return true;
}
var cnas = null;
var ch = {};
ch['nist'] = {n: 'NIST', i: 'https://nvd.nist.gov/'};
ch['cisa-adp'] = {n: 'CISA ADP', i: 'https://www.cisa.gov'};
ch['cve'] = {n: 'CVE', i: 'https://www.cve.org'};
ch['mitre'] = {n: 'MITRE Corporation', i: 'https://www.mitre.org'};
ch['enisa']={n:"EU Agency for Cybersecurity (ENISA)",i:"www.enisa.europa.eu"};
ch["mautic"]={"n":"Mautic","i":"https://mautic.org"};
ch["tianocore"]={"n":"TianoCore.org","i":"https://www.tianocore.org"};
ch["zowe"]={"n":"Zowe","i":"https://www.zowe.org"};
ch["caliptra"]={"n":"Caliptra Project","i":"https://www.chipsalliance.org"};
ch["ob"]={"n":"OceanBase","i":"https://en.oceanbase.com"};

function normalizeShortName(shortName) {
    if (!shortName) return null;
    return String(shortName).trim().toLowerCase().replace(/\s+/g, '_');
}

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
            cnas = JSON.parse(fs.readFileSync(LOCAL_PATH, 'utf8'));
            console.log('✅ Loaded CNAs from local cache.');
        } catch (localError) {
            console.error(`💥 Failed to load local file: ${localError.message}`);
            cnas = {}; // Final fallback
        }
    }

    console.log(`Total CNAs loaded: ${cnas?.length || 0}`);
}

async function getFavicon(u) {
    try {
        const url = 'https://www.google.com/s2/favicons?sz=64&domain_url=' + encodeURIComponent(u);
        const response = await fetch(url);
        if (!response.ok) throw new Error(`unexpected response ${response.statusText}`);
        const b = await response.blob();
        const arrayBuffer = await b.arrayBuffer();
        const buffer = Buffer.from(arrayBuffer);
        const md5 = crypto.createHash('md5').update(buffer, "binary").digest('hex');
        return { md5, buffer };
    } catch(e) {
        throw new Error('failed to get Favicon');
    }
}

async function processCna(c) {
    c.shortName = normalizeShortName(c.shortName);
    let u = new URL('https://www.cve.org/');
    let iconSaved = false;
    try {
        const em = c.contact[0].email[0].emailAddr;
        const host = em.substr(em.indexOf('@') + 1);
        u = new URL('https://www.' + host);
        const { md5, buffer } = await getFavicon(u);
        iconSaved = saveFavicon(c.shortName, buffer, md5);
        console.log(u + ' got ' + md5);
    } catch(er) {
        try {
            u = new URL(c.securityAdvisories.advisories[0].url);
            const faviconUrl = u.protocol + '//' + u.hostname;
            const { md5, buffer } = await getFavicon(faviconUrl);
            iconSaved = saveFavicon(c.shortName, buffer, md5);
            console.log(u + ' got ' + md5);
        } catch(e) {
            try {
                u = new URL(c.disclosurePolicy[0].url);
                const faviconUrl = u.protocol + '//' + u.hostname;
                const { md5, buffer } = await getFavicon(faviconUrl);
                iconSaved = saveFavicon(c.shortName, buffer, md5);
                console.log(u + ' got ' + md5);
            } catch(e) {
                console.log('Error:' + u);
            }
        }
    }

    const baseUrl = u.protocol + '//' + u.hostname;
    if (!ch[c.shortName]) {
        ch[c.shortName] = {
            n: c.organizationName,
            i: baseUrl
        };
    }
    if (!iconSaved) {
        ch[c.shortName].g = 1;
    }

    const iconSrc = fs.existsSync(`./icons/${c.shortName}.png`)
        ? `icons/${c.shortName}.png`
        : `https://www.google.com/s2/favicons?sz=64&domain_url=${ch[c.shortName].i}`;
    return `<div><img src="${iconSrc}"/><a href="/seaview?CNA:${c.shortName}">${c.organizationName}</a></div>`;
}

async function generateCnaList() {
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

    if (!fs.existsSync('./icons')) {
        fs.mkdirSync('./icons');
    }

    const parts = [`<html><head><title>CNA Favicons</title>
<style>
body {
    font-family: sans-serif;
    background-color: #ddd;
}
#iconlist {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(9em, 1fr));
    grid-gap: 0.5em;
}
#iconlist div {
    background-color:#fff;
    padding:0.5em;
    text-align: center;
    min-height: 4em;
    vertical-align:middle;
    box-shadow:2px 2px 5px #9996;
}
#iconlist img {
    margin: 0 auto;
    font-size: 32px;
    display: block;
    border: 1px solid #aaa;
    border-radius: 3px;
    padding:5px;
    width:48px;
    height:48px;
}
#iconlist b {
    font-weight:normal;
    margin-top:1em;
    font-size:small;
}</style>
</head><body><div id="iconlist">`];

    for (let i = 0; i < cnas.length; i += BATCH_SIZE) {
        const batch = cnas.slice(i, i + BATCH_SIZE);
        const batchParts = await Promise.all(batch.map(processCna));
        parts.push(...batchParts);

        if (i + BATCH_SIZE < cnas.length) {
            await new Promise(resolve => setTimeout(resolve, BATCH_DELAY_MS));
        }
    }

    return parts.join('\n');
}

async function main(){
    await fetchCNAs();

    fs.writeFileSync('cna.html', await generateCnaList() + "</div></body></html>");
    fs.writeFileSync('cna.js', 'var cna = ' + JSON.stringify(ch,0,0));
}

main();
