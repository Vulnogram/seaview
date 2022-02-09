const fs = require('fs');
const cnas = require('./CNAsList.json');
const fetch = require('node-fetch');
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const crypto = require('crypto');

ch={};

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

async function getCnaList() {
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
return cnaList;
}

async function main(){
    fs.writeFileSync('cna.html', await getCnaList() + "</div></body></html>");
    fs.writeFileSync('cna.js', 'var cna = ' + JSON.stringify(ch));
}

main();