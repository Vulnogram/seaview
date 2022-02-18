![SeaView Logo](https://vulnogram.github.io/seaview/apple-touch-icon.png)
#  SeaView
 View CVE Records 

[Go to the tool online](https://vulnogram.github.io/seaview)

SeaView (named because CVE-View is a tongue twister) loads CVE JSON 5 documents from [github.com/CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5/) and presents a rendering of the version 4 document next to a version 5 document upconverted using the [CVE_4_to_5_converter](https://github.com/CVEProject/cve-schema/tree/master/schema/v5.0/support/CVE_4_to_5_converter).

## CVE rendering code

It uses Pug-js templating engine to render a JSON document to HTML.

[cve.pug](./cve.pug) --> [build.js](./build.js) --> [cve.js](./cve.js)

The function cve() to get an HTML rendering that is then displayed client side.


## CNA favicons

[buildCnas.js](./buildCnas.js) file loads a JSON listing of CNAs, trys to fetch the favicon using Google's favicon service from the CNA's webistes to. Then [stores them in an object](./cna.js) indexed by CNA's shortName and generates a [thumbnail index](https://vulnogram.github.io/seaview/cna).


