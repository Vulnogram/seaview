function loadQueryString() {
    const queryString = window.location.search;
    document.getElementById("q").value = queryString.substring(1);
    getCVEs(queryString);
}


function extractUniqueCVEs(input) {
  const cvePattern = /\bCVE-(\d{4})-(\d{4,6})\b/g;
  const uniqueCVEs = new Set();
  let match;
 var yearNow = new Date().getFullYear()+2;
  while ((match = cvePattern.exec(input.toUpperCase())) !== null) {
    const year = parseInt(match[1], 10);
    if (year > 1997 && year <= yearNow ) {
      uniqueCVEs.add(match[0]);
    }
  }
  return Array.from(uniqueCVEs).sort((a, b) => {
    const [_, yearA, idA] = a.match(/CVE-(\d{4})-(\d+)/);
    const [__, yearB, idB] = b.match(/CVE-(\d{4})-(\d+)/);
    return yearA !== yearB ? yearA - yearB : idA - idB;
  });
;
}

function getCVEs(input) {
    const container = document.getElementById('container');
    const results = document.getElementById('results');
    const list =  document.getElementById('list');
    var cves = extractUniqueCVEs(input);
    if (cves.length <= 1) {
        list.classList.add('hid');
    }
    if (cves.length >= 1) {
        container.classList.add('moved-up');
        results.classList.add('visible');
        list.innerHTML = '';
        if (cves.length > 1)
            list.classList.remove('hid');
        results.innerHTML = `<p>Valid CVEs: <strong>${cves}</strong></p>`;
        document.getElementById('entries').innerHTML = '';
        cves.forEach(cve => {
            loadCVE(cve);
        });
        document.title = cves.join(' ');
        history.pushState(null, null, "?"+cves);
    } else {
        results.classList.add('visible');
        results.innerHTML = `Please enter one or more valid CVE IDs <i>CVE-year-nnnn</i> format.`;
    }
}

function loadCVE(value) {
    var realId = value.match(/(CVE-(\d{4})-(\d{1,12})(\d{3}))/);
    if (realId) {
        var id = realId[1];
        var year = realId[2];
        var bucket = realId[3];
        var jsonURL = 'https://github.com/CVEProject/cvelistV5/blob/main/cves/' + year + '/' + bucket + 'xxx/' + id + '.json'
        fetch('https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/' + year + '/' + bucket + 'xxx/' + id + '.json', {
                method: 'GET',
                credentials: 'omit',
                headers: {
                    'Accept': 'application/json, text/plain, */*'
                },
                redirect: 'error'
            })
            .then(function (response) {
                if (!response.ok) {
                    throw Error('Failed to load ' + id + ' ' + response.statusText);
                }
                return response.json();
            })
            .then(function (res) {
                if (res.containers) {
                    loadEntry(res, id);
                } else {
                    results.textContent = results.textContent + " Failed to load " + id;
                }
            })
            .catch(function (error) {
                results.textContent = results.textContent + ' ' +error.message ;
            })
    } else {
        //console.log("CVE ID required");
    }
    return false;
}

// adds an element to the array if it does not already exist using a comparer 
// function
function addUniq(array, element) {
    var index = array.indexOf(element);
    if (index === -1) {
        array.push(element);
    }
};


function versionStatusTable4(affects) {
    var collator = new Intl.Collator(undefined, {numeric: true});
    nameAndPlatforms = {};
    var table= {
        affected: {},
        unaffected: {},
        unknown: {}
    };
    var showCols = {
        platforms: false,
        affected: false,
        unaffected: false,
        unknown: false
    };
    for (var vendor of affects.vendor.vendor_data) {
        var vendor_name = vendor.vendor_name;
        for(var product of vendor.product.product_data) {
            var product_name = product.product_name;
            for(var version of product.version.version_data) {
                var vv = version.version_value;
                var cat = "affected";
                var platforms = "";
                var major = version.version_name ? version.version_name : "";
                if(!version.version_affected && version.affected) { 
                    version.version_affected = version.affected;
                }
                if(version.version_affected) {
                    if(version.version_affected.startsWith('?')) {
                        cat = "unknown";
                    } else if (version.version_affected.startsWith('!')) {
                        cat = "unaffected";
                    }
                    switch (version.version_affected) {
                        case "!":
                        case "?":
                        case "=":
                            vv = version.version_value;
                            break;
                        case "<":
                        case "!<":
                        case "?<":
                            vv = "< " + version.version_value;
                            break;
                        case ">":
                        case "!>":
                        case "?>":
                            vv = "> " + version.version_value;
                            break;
                        case "<=":
                        case "!<=":
                        case "?<=":
                            vv = "<= " + version.version_value;
                            break;
                        case ">=":
                        case "!>=":
                        case "?>=":
                            vv = ">= " + version.version_value;
                            break;
                        default:
                            vv = version.version_value;
                    }
                }
                if (cat)
                    showCols[cat] = true;
                if (version.platform && version.platform != "") {
                    showCols.platforms = true;
                    platforms = version.platform;
                }
                var pFullName = [(vendor_name? vendor_name + ' ': '') + product_name + (major ? ' ' + major : ''), platforms];
                nameAndPlatforms[pFullName] = pFullName;                
                if(!table[cat][pFullName]) {
                    table[cat][pFullName] = [];
                }
                if (vv) {
                    table[cat][pFullName].push(vv);
                }
            }
        }
    }
    return({cols:nameAndPlatforms, vals:table, show: showCols});
}

/* fullname = vendor . product . platforms . module .others 
/* table --> [ fullname ][version][affected|unaffected|unknown] = [ list of ranges ] */
function versionStatusTable5(affected) {
    var t = {};
    nameAndPlatforms = {};
    var showCols = {
        platforms: false,
        modules: false,
        affected: false,
        unaffected: false,
        unknown: false
    };
    for(var p of affected) {
        var pname = p.product ? p.product : p.packageName ? p.packageName : '';
        if (p.platforms)
            showCols.platforms = true;
        if (p.modules)
            showCols.modules = true;
        if (p.status)
            showCols[p.status] = true;
        var platforms =
            (p.platforms ? p.platforms.join(', '): '');
        var others = {};
        if(p.collectionURL) {
            others.collectionURL = p.collectionURL;
        }
        if(p.repo) {
            others.repo = p.repo;
        }
        if(p.programFiles) {
            others.programFiles = p.programFiles;
        }
        if(p.programRoutines) {
            others.programRoutines = p.programRoutines;
        }
        //pname = pname + platforms;
        var modules = p.modules ? p.modules.join(', ') : '';
        if(p.versions) {
            for(v of p.versions) {
                var rows = {
                    affected: [],
                    unaffected: [],
                    unknown: []
                };
                var major = undefined;//major ? major[1] : '';
                var pFullName = [(p.vendor ? p.vendor + ' ' : '') + pname + (major ? ' ' + major : ''), platforms, modules, others];
                nameAndPlatforms[pFullName] = pFullName;
                if (v.version) {
                    showCols[v.status] = true;
                    if(!v.changes) {
                        var rangeStart = '';
                        if (v.version != 'unspecified' && v.version !=  0)
                            rangeStart = 'from ' + v.version;
                        if(v.lessThan) {
                            var rangeEnd = ' before ' + v.lessThan;
                            if(v.lessThan == 'unspecified' || v.lessThan == '*')
                                rangeEnd = "";
                            rows[v.status].push(rangeStart + rangeEnd);
                        } else if(v.lessThanOrEqual) {
                            var rangeEnd = ' through ' + v.lessThanOrEqual;
                            if (v.lessThanOrEqual == 'unspecified' || v.lessThanOrEqual == '*')
                                rangeEnd = "";
                            rows[v.status].push(rangeStart + rangeEnd);
                        } else {
                            rows[v.status].push(v.version);
                        }
                    } else {
                        var prevStatus = v.status;
                        var prevVersion = v.version;
			            showCols[prevStatus] = true;
                        var range = '';
                        if (prevVersion != 'unspecified' && prevVersion !=  0)
                            range = 'from ' + prevVersion;
                        if(v.lessThan) {
                            var rangeEnd = ' before ' + v.lessThan;
                            if(v.lessThan == 'unspecified' || v.lessThan == '*')
                                rangeEnd = "";
                            range = range + (v.lessThan != prevVersion ? rangeEnd : '');
                        } else if(v.lessThanOrEqual) {
                            var rangeEnd = ' through ' + v.lessThanOrEqual;
                            if (v.lessThanOrEqual == 'unspecified' || v.lessThanOrEqual == '*')
                                rangeEnd = "";                            
                                range = range + (v.lessThanOrEqual != prevVersion ? rangeEnd : '');
                        } else {
                            range = prevVersion;
                        }
                        var changes  = [];
                        for(c of v.changes) {
                            changes.push(c.status + ' from ' + c.at);
                        }
                        if(changes.length > 0) {
                            range = range + ' (' + changes.join(', ') + ')';
                        }
                        rows[v.status].push(range);
                    }
                }
                if(!t[pFullName]) t[pFullName] = [];
                //if(!t[pFullName][v.version]) t[pFullName][v.version] = [];
                t[pFullName].push(rows);
            }
        }
        var pFullName = [(p.vendor ? p.vendor + ' ' : '') + pname + (major ? ' ' + major : ''), platforms, modules, others];
        nameAndPlatforms[pFullName] = pFullName;
        var rows = {};
        if (p.defaultStatus) {
            rows[p.defaultStatus] = ["everything else"];
            showCols[p.defaultStatus] = true;
            if(!t[pFullName]) {
                t[pFullName] = [rows];
            } else {
                t[pFullName].push(rows);
            }
        }
    }
    return({groups:nameAndPlatforms, vals:t, show: showCols});
}



cvssDesc = {
    "attackVector": {
        "NETWORK": "Worst: The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed “remotely exploitable” and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers)."
        ,
        "ADJACENT": "Worse: The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone). One example of an Adjacent attack would be an ARP (IPv4) or neighbor discovery (IPv6) flood leading to a denial of service on the local LAN segment."
        ,
        "LOCAL": "Bad: The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: <ul><li>the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH);</li><li>or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).</li></ul>"
        ,
        "PHYSICAL": "Bad: The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief (e.g., evil maid attack) or persistent. An example of such an attack is a cold boot attack in which an attacker gains access to disk encryption keys after physically accessing the target system. Other examples include peripheral attacks via FireWire/USB Direct Memory Access (DMA)."
    },
    "attackComplexity": {
        "LOW": "Worst: Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component."
        ,
        "HIGH": "Bad: A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected."
    },
    "privilegesRequired": {
        "NONE": "Worst: The attacker is unauthorized before the attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack."
        ,
        "LOW": "Worse The attacker requires privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with low privileges can access only non-sensitive resources."
        ,
        "HIGH":"Bad: The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable component allowing access to component-wide settings and files."
        
    },
    "userInteraction": {
        "NONE": "Worst: The vulnerable system can be exploited without interaction from any user."
        ,
        "REQUIRED": "Bad: Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. For example, a successful exploit may only be possible during the installation of an application by a system administrator."
    },
    "scope": {
        "CHANGED": "Worst: An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.",
        "UNCHANGED": "Bad: An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority."
    },
    "confidentialityImpact": {
        "HIGH": "Worst: There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server.",
        "LOW": "Bad: There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component.",
        "NONE": "Good: There is no loss of confidentiality within the impacted component."
    },
    "integrityImpact": {
        "HIGH": "Worst: There is a total loss of integrity or a complete loss of protection. For example, the attacker can modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.",
        "LOW": "Bad: Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.",
        "NONE": "Good: There is no loss of integrity within the impacted component."
    },
    "availabilityImpact": {
        "HIGH": "Worst: There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker can deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks an only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).",
        "LOW": "Bad: Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker cannot completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.",
        "NONE": "Good: There is no impact on availability within the impacted component."
    }
}

function loadEntry(d, id, msg, msgLink) {
    var entries = document.getElementById("entries");
    var entryDiv = document.createElement("div");
    var entry = cve({renderTemplate:'entry', d: d, statusFunctionv4:versionStatusTable4, statusFunctionv5:versionStatusTable5});
    entryDiv.innerHTML = entry;
    entries.appendChild(entryDiv);

    var table = document.getElementById("list");
    var tableEntry = document.getElementById('i'+id);
    table.appendChild(tableEntry);
}