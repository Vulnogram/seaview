![SeaView Logo](https://vulnogram.org/seaview/seaview.jpg)
#  [SeaView](https://vulnogram.org/seaview) -  an online tool to Extract and View CVE Records


[Go to the tool online](https://vulnogram.org/seaview)

SeaView (named because CVE-View is a tongue twister) identifies CVE ids in a given text and shows them, else searches for given keywords CVE records, loads the records from [github.com/CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5/) and presents a more complete rendering of most of the information in the record, like the fix and workaround information that may not be shown on cve.org

## CVE rendering code

It uses Pug-js templating engine to render a JSON document to HTML.

[cve.pug](./cve.pug) --> [build.js](./build.js) --> [cve.js](./cve.js)

The function cve() to get an HTML rendering that is then displayed client side.


## CNA favicons

[buildCnas.js](./buildCnas.js) file loads a JSON listing of CNAs, trys to fetch the favicon using Google's favicon service from the CNA's webistes to. Then [stores them in an object](./cna.js) indexed by CNA's shortName and generates a [thumbnail index](https://vulnogram.org/seaview/cna).


