const fs = require('fs');
const fetch = require('node-fetch');
const crypto = require('crypto');
const { cna: previousCnas, cnaTypes } = require('./cna');
const REMOTE_URL = 'https://raw.githubusercontent.com/CVEProject/cve-website/main/src/assets/data/CNAsList.json';
const BATCH_SIZE = 5;
const BATCH_DELAY_MS = 300;
const GENERIC_FAVICON_MD5 = '81addaa406504038756c8f1613668203';

function saveFavicon(shortName, buffer, md5) {
    if (md5 === GENERIC_FAVICON_MD5 && !shortName.includes('github')) return false;
    fs.writeFileSync(`./icons/${shortName}.png`, buffer);
    return true;
}
var cnas = null;
// Keep historical providers as well as active CNAs for rendering older CVEs.
var ch = { ...previousCnas }, chi={};
const previousById = new Map(Object.values(previousCnas).filter(c => c.id).map(c => [c.id, c]));
chi['nist'] = {n: 'NIST', i: 'https://nvd.nist.gov/', t: cnaTypes.indexOf('Government')};
chi['cisa-adp'] = {n: 'CISA ADP', i: 'https://www.cisa.gov', t: cnaTypes.indexOf('Government')};
chi['cve'] = {n: 'CVE', i: 'https://www.cve.org', t: 0};
chi['mitre'] = {n: 'MITRE Corporation', i: 'https://www.mitre.org'};
chi['enisa']={n:"EU Agency for Cybersecurity (ENISA)",i:"www.enisa.europa.eu"};
chi["mautic"]={"n":"Mautic","i":"https://mautic.org"};
chi["tianocore"]={"n":"TianoCore.org","i":"https://www.tianocore.org"};
chi["zowe"]={"n":"Zowe","i":"https://www.zowe.org"};
chi["caliptra"]={"n":"Caliptra Project","i":"https://www.chipsalliance.org"};
chi["ob"]={"n":"OceanBase","i":"https://en.oceanbase.com"};

function normalizeShortName(shortName) {
    if (!shortName) return null;
    return String(shortName).trim().toLowerCase().replace(/\s+/g, '_');
}

async function fetchCNAs() {
    const response = await fetch(REMOTE_URL);
    if (!response.ok) {
        throw new Error(`CNA fetch failed: HTTP ${response.status}`);
    }
    const incoming = await response.json();
    if (!Array.isArray(incoming) || !incoming.length || incoming.some(c => !c.cnaID || !c.shortName || !c.organizationName)) {
        throw new Error('Invalid or empty upstream CNA list');
    }
    cnas = incoming;
    console.log(`Total CNAs loaded: ${cnas.length}`);
    const unknown = cnas.filter(c => !previousById.get(c.cnaID)?.t);
    if (unknown.length) {
        console.warn(`Organization types need review (${unknown.length}): ${unknown.map(c => c.shortName).join(', ')}`);
    }
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
    const originalShortName = c.shortName;
    c.shortName = normalizeShortName(c.shortName);
    // Preserve distinct providers whose names normalize to the same key.
    // For example, Snow (Snow Software) and SNOW (Snowflake).
    const key = ch[c.shortName]?.id && ch[c.shortName].id !== c.cnaID
        ? originalShortName : c.shortName;
    const iconKey = key === c.shortName ? c.shortName : normalizeShortName(c.cnaID);
    let u = new URL('https://www.cve.org/');
    let iconSaved = false;
    try {
        const em = c.contact[0].email[0].emailAddr;
        const host = em.substr(em.indexOf('@') + 1);
        u = new URL('https://www.' + host);
        const { md5, buffer } = await getFavicon(u);
        iconSaved = saveFavicon(iconKey, buffer, md5);
        console.log(u + ' got ' + md5);
    } catch(er) {
        try {
            u = new URL(c.securityAdvisories.advisories[0].url);
            const faviconUrl = u.protocol + '//' + u.hostname;
            const { md5, buffer } = await getFavicon(faviconUrl);
            iconSaved = saveFavicon(iconKey, buffer, md5);
            console.log(u + ' got ' + md5);
        } catch(e) {
            try {
                u = new URL(c.disclosurePolicy[0].url);
                const faviconUrl = u.protocol + '//' + u.hostname;
                const { md5, buffer } = await getFavicon(faviconUrl);
                iconSaved = saveFavicon(iconKey, buffer, md5);
                console.log(u + ' got ' + md5);
            } catch(e) {
                console.log('Error:' + u);
            }
        }
    }

    const baseUrl = u.protocol + '//' + u.hostname;
    ch[key] = {
        n: c.organizationName,
        i: baseUrl,
        s: originalShortName,
        id: c.cnaID,
        t: previousById.get(c.cnaID)?.t ?? 0
    };
    if (!iconSaved) {
        ch[key].g = 1;
    }
 
    if (chi[c.shortName]) {
        Object.assign(ch[key], chi[c.shortName]);
    }

    const iconSrc = fs.existsSync(`./icons/${iconKey}.png`)
        ? `icons/${iconKey}.png`
        : `https://www.google.com/s2/favicons?sz=64&domain_url=${ch[key].i}`;
    return `<div><img src="${iconSrc}"/><a href="/seaview?CNA:${encodeURIComponent(originalShortName)}">${c.organizationName}</a></div>`;
}

async function generateCnaList() {

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
    for (const [k, v] of Object.entries(chi)) {
        if (!ch[k]) ch[k] = { s: k, t: 0, ...v };
    }
    fs.writeFileSync('cna.js', 'var cnaTypes=' + JSON.stringify(cnaTypes)
        + ';var cna=' + JSON.stringify(ch)
        + ';if(typeof module!=="undefined")module.exports={cna,cnaTypes};\n');
}

if (require.main === module) {
    main().catch(error => {
        console.error(`CNA build failed: ${error.message}`);
        process.exitCode = 1;
    });
}

module.exports = { main };
