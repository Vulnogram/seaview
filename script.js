function loadQueryString() {
    const queryString = window.location.search;
    if(queryString && queryString.length >= 1) {
        var q = decodeURIComponent(queryString.substring(1));
        document.getElementById("q").value = q
        if (q) {
            getCVEs(q);
            handleHashChange();
        }
    }
}

function handleHashChange() {
    // 1. Extract the raw fragment, remove the leading '#'
    const rawHash = window.location.hash;
    const fragment = rawHash.startsWith('#') ? rawHash.substring(1) : rawHash;

    if (!fragment) {
        return;
    }
    
    if (isValidCveFormat(fragment)) {
        loadEntry(fragment);
    }
}
window.addEventListener('hashchange', handleHashChange);

function isValidCveFormat(id) {
    // Regex for 'CVE-YYYY-NNNN+' (case-insensitive for robustness)
    // It requires "cve-", followed by 4 digits, followed by '-', and at least 4 more digits.
    const cveRegex = /^cve-\d{4}-\d{4,}$/i;
    return cveRegex.test(id);
}

function extractUniqueCVEs(input) {
  const cvePattern = /CVE-(\d{4})-(\d{4,6})/g;
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

const CNA_REGEX = /CNA:(\"([^\"]+)\"|([^\s]+))/i;

async function fetchCnaCveList(uuid) {
    var url = 'https://raw.githubusercontent.com/Vulnogram/cve-index/refs/heads/main/latest/' + uuid + '.json';
    var response = await fetch(url, {
        method: 'GET',
        credentials: 'omit',
        headers: {
            'Accept': 'application/json, text/plain, */*'
        },
        redirect: 'error'
    });
    if (!response.ok) {
        throw Error('Failed to load CNA list ' + uuid + ' ' + response.statusText);
    }
    var data = await response.json();
    if (!Array.isArray(data)) {
        return [];
    }
    var seen = new Set();
    var normalized = [];
    data.forEach(function (id) {
        var rawId = ('' + id).trim();
        if (!rawId) {
            return;
        }
        var formatted = rawId.toUpperCase();
        if (!formatted.startsWith('CVE-')) {
            formatted = 'CVE-' + formatted;
        }
        if (!seen.has(formatted)) {
            seen.add(formatted);
            normalized.push(formatted);
        }
    });
    return normalized;
}
var cnaSearchID = '';
async function resolveCnaCves(text) {
    if (!text) {
        return [];
    }
    var match = text.match(CNA_REGEX);
    if (!match) {
        return [];
    }
    try {
        cnaSearchID = match[1];
        return await fetchCnaCveList(match[1]);
    } catch (err) {
        console.warn('Unable to fetch CNA CVE list', err);
        return [];
    }
}

const SEARCH_PAGE_SIZE = 30;

var searchState = {
    query: '',
    items: [],
    nextCursor: null,
    loading: false
};

var manualListState = {
    active: false,
    allItems: [],
    nextIndex: 0
};

function resetManualListState() {
    manualListState.active = false;
    manualListState.allItems = [];
    manualListState.nextIndex = 0;
}

function resetSearchState(query = '') {
    searchState.query = query;
    searchState.items = [];
    searchState.nextCursor = null;
    searchState.loading = false;
}

function updateLoadMoreButton() {
    var button = document.getElementById('loadMoreBtn');
    if (!button) {
        return;
    }
    var manualHasMore = manualListState.active && manualListState.nextIndex < manualListState.allItems.length;
    var searchHasMore = Boolean(searchState.query) &&
        searchState.items.length > 0 &&
        searchState.nextCursor !== null;
    var shouldShow = manualHasMore || searchHasMore;
    button.classList.toggle('hid', !shouldShow);
    button.disabled = searchState.loading;
    if (shouldShow) {
        button.textContent = searchState.loading ? 'Loading...' : 'Load more';
    }
}

function updateStatusTextMessage(cveList, textSearch) {
    var statusText = document.getElementById('statusText');
    if (!statusText || !Array.isArray(cveList)) {
        return;
    }
    var count = cveList.length;
    var hasMore = false;
    if (textSearch) {
        hasMore = searchState.nextCursor !== null;
    } else if (manualListState.active) {
        hasMore = manualListState.nextIndex < manualListState.allItems.length;
    }
    var plus = hasMore ? '+' : '';
    var plural = count === 1 ? '' : 's';
    statusText.innerText = `Found ${count}${plus} CVE${plural}: ${cveList.join(', ')}`;
}
function clearURL() {
  history.replaceState && history.replaceState(
  null, '', location.pathname
);
}

var entryView = false;
var multiResultMode = false;
var selectedEntryId = null;
var listPanelWidth = 320;
var listPanelMinWidth = 220;
var listPanelMaxWidth = 1200;
var userResizedList = false;

function getPanelList() {
    return document.querySelector('.panel-list');
}

function getLayoutRoot() {
    return document.getElementById('masterDetail');
}

function setInlineListWidth(width) {
    var panelList = getPanelList();
    if (!panelList) {
        return;
    }
    listPanelWidth = width;
    panelList.style.flex = '0 0 ' + width + 'px';
    panelList.style.flexBasis = width + 'px';
    panelList.style.width = width + 'px';
}

function clearInlineListWidth() {
    var panelList = getPanelList();
    if (!panelList) {
        return;
    }
    panelList.style.removeProperty('flex');
    panelList.style.removeProperty('flex-basis');
    panelList.style.removeProperty('width');
}

function resetListPanelSizing() {
    userResizedList = false;
    listPanelWidth = 320;
    clearInlineListWidth();
    var layout = getLayoutRoot();
    if (layout) {
        layout.classList.remove('resized');
    }
}

function setSplitMode(isSplit) {
    var layout = getLayoutRoot();
    multiResultMode = isSplit;
    if (!layout) {
        return;
    }
    layout.classList.toggle('split', isSplit);
    layout.classList.toggle('single', !isSplit);
    layout.dataset.state = isSplit ? 'list' : 'detail';
    if (!isSplit) {
        resetListPanelSizing();
        return;
    }
    layout.classList.remove('resized');
    clearInlineListWidth();
}

function setLayoutState(state) {
    var layout = getLayoutRoot();
    if (!layout) {
        return;
    }
    layout.dataset.state = state;
    if (!multiResultMode) {
        return;
    }
    if (state === 'detail' && userResizedList) {
        layout.classList.add('resized');
        setInlineListWidth(listPanelWidth);
    }
    if (state === 'list') {
        window.scrollTo(0,listPosition);
        layout.classList.remove('resized');
        if (userResizedList) {
            clearInlineListWidth();
        }
    }
}

function showListPanel() {
    if (!multiResultMode) {
        return;
    }
    setLayoutState('list');
}

function showDetailPanel() {
    window.scrollTo(0,0);
    setLayoutState('detail');
}

function highlightRow(id) {
    if (selectedEntryId) {
        var previousRow = document.getElementById('i' + selectedEntryId);
        if (previousRow) {
            previousRow.classList.remove('selected');
        }
    }
    selectedEntryId = id || null;
    if (!selectedEntryId) {
        return;
    }
    var currentRow = document.getElementById('i' + selectedEntryId);
    if (currentRow) {
        currentRow.classList.add('selected');
        listPosition = window.scrollY;
    }
}

function clampListWidth(width) {
    var layout = getLayoutRoot();
    var layoutWidth = layout ? layout.getBoundingClientRect().width : window.innerWidth;
    var dynamicMax = Math.max(listPanelMinWidth, Math.min(listPanelMaxWidth, layoutWidth - listPanelMinWidth));
    if (!Number.isFinite(dynamicMax) || dynamicMax < listPanelMinWidth) {
        dynamicMax = listPanelMaxWidth;
    }
    return Math.max(listPanelMinWidth, Math.min(dynamicMax, width));
}

function setupSplitterResize() {
    var splitter = document.querySelector('.splitter');
    var panelList = getPanelList();
    if (!splitter || !panelList) {
        return;
    }
    var dragging = false;
    var startX = 0;
    var startWidth = 0;
    var layout = getLayoutRoot();
    var isDesktop = () => !window.matchMedia('(max-width: 768px)').matches;

    function stopDrag() {
        if (!dragging) {
            return;
        }
        dragging = false;
        document.body.classList.remove('resizing');
        panelList.classList.remove('resizing');
        window.removeEventListener('pointermove', onPointerMove);
        window.removeEventListener('pointerup', stopDrag);
        window.removeEventListener('pointercancel', stopDrag);
    }

    function onPointerMove(evt) {
        if (!dragging) {
            return;
        }
        var delta = evt.clientX - startX;
        var newWidth = clampListWidth(startWidth + delta);
        setInlineListWidth(newWidth);
    }

    splitter.addEventListener('pointerdown', function (evt) {
        if (!multiResultMode || !isDesktop()) {
            return;
        }
        dragging = true;
        userResizedList = true;
        layout = getLayoutRoot();
        startX = evt.clientX;
        var currentWidth = panelList.getBoundingClientRect().width;
        layout && layout.classList.add('resized');
        setInlineListWidth(currentWidth);
        startWidth = listPanelWidth;
        document.body.classList.add('resizing');
        panelList.classList.add('resizing');
        window.addEventListener('pointermove', onPointerMove);
        window.addEventListener('pointerup', stopDrag);
        window.addEventListener('pointercancel', stopDrag);
        evt.preventDefault();
    });
}
async function getCVEs(text) {
    const container = document.getElementById('container');
    const backButton = document.getElementById('backButton');
    container.classList.add('busy');
    backButton.classList.add('hid');
    const results = document.getElementById('results');
    const list =  document.getElementById('idxTble');
    const statusText = document.getElementById('statusText');
    resetSearchState();
    resetManualListState();
    updateLoadMoreButton();
    //resetSort(list.parentElement);
    var textSearch = false;
    var cnaSearch = false;
    var cves = await resolveCnaCves(text);
    if (cves.length === 0) {
        cves = extractUniqueCVEs(text);
    } else {
        cnaSearch = true;
    }
    if (cves.length === 0) {
        if(text.length > 0 && text.length <= 100) {
            textSearch = true;
            searchState.query = text;
            searchState.loading = true;
            updateLoadMoreButton();
            const initialResults = await searchCve(text, { cursor: 0, pageSize: SEARCH_PAGE_SIZE });
            searchState.loading = false;
            if(initialResults && initialResults.items && initialResults.items.length > 0) {
                searchState.items = initialResults.items.slice();
                searchState.nextCursor = initialResults.nextCursor ?? null;
                cves = searchState.items.slice();
            } else {
                resetSearchState();
                clearURL();
                results.classList.add('visible');
                document.getElementById('entry').innerHTML = '';
                statusText.innerText = `No matching CVEs found. Please enter CVE IDs CVE-year-nnnn or fewer keywords.`;
            }
            updateLoadMoreButton();
        } else {
            clearURL();
            results.classList.add('visible');
            document.getElementById('entry').innerHTML = '';
            statusText.innerText = `Please enter one or more valid CVE IDs CVE-year-nnnn format or fewer keywords.`;
        }
    }
    entryView = !textSearch && (cves.length == 1);
    resetListPanelSizing();
    var shouldSplit = textSearch ? cves.length >= 1 : cves.length > 1;
    setSplitMode(shouldSplit);
    if (cves.length >= 1) {
        if (!textSearch) {
            clearURL();
        }
        container.classList.add('moved-up');
        results.classList.add('visible');
        list.innerHTML = '';
        highlightRow(null);
        if (cves.length > 1 || textSearch)
            list.parentElement.classList.remove('hid');
        var displayList = cves;
        if (!textSearch && cves.length > SEARCH_PAGE_SIZE) {
            manualListState.active = true;
            manualListState.allItems = cves.slice();
            manualListState.nextIndex = SEARCH_PAGE_SIZE;
            displayList = manualListState.allItems.slice(0, SEARCH_PAGE_SIZE);
        }
        var statusValues = textSearch ? searchState.items : displayList;
        updateStatusTextMessage(statusValues, textSearch);
        document.getElementById('entry').innerHTML = '';
        displayList.forEach(cve => {
            addContainer(cve);
        });
        displayList.forEach(cve => {
            loadCVE(cve);
        });
        if(textSearch) {
            document.title = text;
            history.pushState({text:text}, null, "?"+encodeURIComponent(text));
        } else if (cnaSearch) {
            //document.title = 'Recent ' + cves[0].cveMetadata.assignerShortName;
            history.pushState({cves:cves}, null, "?CNA:" + cnaSearchID);
        } else {
            document.title = cves.join(' ');
            history.pushState({cves:cves}, null, "?"+cves);
        }
        updateLoadMoreButton();
    }
    if (cves.length>1) {
        backButton.classList.remove('hid');
    }
    if (textSearch && cves.length >= 1) {
        list.parentElement.classList.remove('hid');
    } else if (cves.length <= 1) {
        list.parentElement.classList.add('hid');
    }
    if (entryView) {
        showDetailPanel();
    } else {
        showListPanel();
    }
    setTimeout(function(){container.classList.remove('busy')},1000);
}

var cveCache = {};
var entryCache = {};

function fetchCveJson(url, id) {
    return fetch(url, {
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
        });
}

function loadCVE(value) {
    var realId = value.match(/(CVE-(\d{4})-(\d{1,12})(\d{3}))/);
    if (realId) {
        var id = realId[1];
        var year = realId[2];
        var bucket = realId[3];
        var jsonURL = 'https://github.com/CVEProject/cvelistV5/blob/main/cves/' + year + '/' + bucket + 'xxx/' + id + '.json'
        var rawUrl = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/' + year + '/' + bucket + 'xxx/' + id + '.json';
        var cveAwgUrl = 'https://cveawg.mitre.org/api/cve/' + id;
        fetchCveJson(rawUrl, id)
            .catch(function (primaryError) {
                //console.warn('Primary CVE source failed for ' + id, primaryError);
                return fetchCveJson(cveAwgUrl, id);
            })
            .then(function (res) {
                if (res.containers) {
                    preProcess(res);
                    cveCache[id] = res;
                    delete entryCache[id];
                    if (entryView) {
                        loadEntry(id);
                    } else {
                        loadItem(res);
                    }
                } else {
                    statusText.textContent = statusText.textContent + " Failed to load " + id;
                }
            })
            .catch(function (error) {
                statusText.textContent = statusText.textContent + ' ' + error.message;
            })
    } else {
        //console.log("CVE ID required");
    }
    return false;
}

async function loadMoreResults() {
    var manualHasMore = manualListState.active && manualListState.nextIndex < manualListState.allItems.length;
    if (manualHasMore) {
        var nextManualItems = manualListState.allItems.slice(manualListState.nextIndex, manualListState.nextIndex + SEARCH_PAGE_SIZE);
        manualListState.nextIndex += nextManualItems.length;
        nextManualItems.forEach(function (cveId) {
            addContainer(cveId);
        });
        nextManualItems.forEach(function (cveId) {
            loadCVE(cveId);
        });
        updateStatusTextMessage(manualListState.allItems.slice(0, manualListState.nextIndex), false);
        updateLoadMoreButton();
        return;
    }
    if (!searchState.query || searchState.nextCursor === null || searchState.loading) {
        return;
    }
    searchState.loading = true;
    updateLoadMoreButton();
    try {
        const nextPage = await searchCve(searchState.query, {
            cursor: searchState.items.length,
            pageSize: SEARCH_PAGE_SIZE
        });
        if (nextPage && Array.isArray(nextPage.items) && nextPage.items.length > 0) {
            nextPage.items.forEach(cveId => {
                addContainer(cveId);
            });
        }
        if (nextPage && Array.isArray(nextPage.items) && nextPage.items.length > 0) {
            nextPage.items.forEach(cveId => {
                searchState.items.push(cveId);
                loadCVE(cveId);
            });
        }
        searchState.nextCursor = nextPage && nextPage.nextCursor !== null ? nextPage.nextCursor : null;
        if (searchState.items.length > 0) {
            updateStatusTextMessage(searchState.items, true);
        }
    } catch (err) {
        console.error('Failed to load more results', err);
    } finally {
        searchState.loading = false;
        updateLoadMoreButton();
    }
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

/**
 * Takes an ISO date-time string and renders it in a user-friendly format
 * based on its recency.
 *
 * - If the date is today, shows the local time (e.g., "12:43 PM").
 * - If the date is this year (but not today), shows "MMM DD" (e.g., "Nov 14").
 * - If the date is a previous year, shows "YYYY MMM DD" (e.g., "2024 Nov 14").
 *
 * @param {string} isoString A string representing a date in ISO format.
 * @returns {string} A formatted, user-friendly date string.
 */
function formatFriendlyDate(isoString) {
  const date = new Date(isoString);
  const now = new Date();

  // Create date objects for comparison, stripping out the time part.
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const inputDateOnly = new Date(date.getFullYear(), date.getMonth(), date.getDate());

  // Case 1: The date is today
  if (inputDateOnly.getTime() === today.getTime()) {
    return date.toLocaleTimeString(undefined, {
      hour: 'numeric',
      minute: '2-digit',
    });
  }

  // Case 2: The date is this year (but not today)
  if (date.getFullYear() === now.getFullYear()) {
    return date.toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
    });
  }

  // Case 3: The date is from a previous year
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}
function preProcess(cve, statusFn) {
    if (!cve || !cve.containers) {
        return {}
    }
    var oldJSON = structuredClone(cve);
    cve.oldJSON = oldJSON;
    var con = cve.containers.cna ? cve.containers.cna : {};
    var CDM = cve.cveMetadata || {};
    con.state = CDM.state;
    con.cveId = CDM.cveId;

    var PMD = con.providerMetadata || {};
    con.dateUpdated = PMD.dateUpdated;
    con.date = CDM.datePublished || con.dateUpdated;
    con.shortName = PMD.shortName;

    con.cvssList = [];
    con.maxCVSS = 0;

    var statusCalculator = statusFn || (typeof versionStatusTable5 === 'function' ? versionStatusTable5 : null);
    con.pvstatus = con.affected && statusCalculator ? statusCalculator(con.affected) : null;

    function normalizeList(list) {
        if (!list) {
            return [];
        }
        return Array.isArray(list) ? list : Object.keys(list).map(function (key) {
            return list[key];
        });
    }

    function updateMaxScore(cvss) {
        if (cvss && typeof cvss.baseScore === 'number' && con.maxCVSS < cvss.baseScore) {
            con.maxCVSS = cvss.baseScore;
        }
    }

    normalizeList(con.metrics).forEach(function (metric) {
        var cvss = metric.cvssV4_0 || metric.cvssV3_1 || metric.cvssV3_0 || metric.cvssV2_0 || null;
        if (cvss) {
            cvss.scenarios = metric.scenarios;
            con.cvssList.push(cvss);
            updateMaxScore(cvss);
        }
    });

    var adpContainers = normalizeList(cve.containers.adp);
    adpContainers.forEach(function (adp) {
        adp.cvssList = [];
        normalizeList(adp.metrics).forEach(function (metric) {
            var cvss = metric.cvssV4_0 || metric.cvssV3_1 || metric.cvssV3_0 || metric.cvssV2_0 || null;
            if (cvss) {
                cvss.scenarios = metric.scenarios;
                adp.cvssList.push(cvss);
                con.cvssList.push(cvss);
                updateMaxScore(cvss);
            }
            if (metric.other && metric.other.type === 'kev') {
                adp.KEV = metric.other.content;
                cve.KEV = true;
            }
        });

        var provider = adp.providerMetadata || {};
        adp.dateUpdated = provider.dateUpdated;
        adp.shortName = provider.shortName;
        adp.cveId = con.cveId;
    });

    return cve;
}

function addContainer(cveId) {
    var list = document.getElementById("idxTble");
    var rowElem = document.createElement('div');
    rowElem.id = 'i' + cveId;
    list.appendChild(rowElem);
}

function loadItem(d) {
    var row = cve({renderTemplate:'row', d: d});
    var container = document.getElementById('i' + d.containers.cna.cveId);
    container.innerHTML = row;
}


function loadEntry(id) {
    if (cveCache[id]) {
        var entry = document.getElementById("entry");
        if(!entryCache[id]) {
            entryCache[id] = cve({ renderTemplate: 'entry', d: cveCache[id], statusFunctionv4: versionStatusTable4, statusFunctionv5: versionStatusTable5 });
        }
        entry.innerHTML = entryCache[id];
        highlightRow(id);
        showDetailPanel();
    } else {
        console.log(' no entry '+id)
    }
}

/**
 * Search JSON files in CVEProject/cvelistV5 whose **contents** contain `searchText`,
 * then return CVE IDs extracted from the **file names**. Results are paged (100 by default).
 *
 * @param {string} searchText - literal text to search within file contents
 * @param {Object} [opts]
 * @param {number} [opts.cursor=0] - zero-based offset into the result set (e.g., 0, 100, 200, …)
 * @param {number} [opts.pageSize=50] - number of items to return
 * @param {number} [opts.timeoutMs=30000] - safety timeout
 * @returns {Promise<{ items: Array<{cveId:string,path:string,blobUrl:string,rawUrl:string }>,
 *                     nextCursor: number|null, totalSoFar:number, done:boolean }>}
 */
async function searchCve(searchText, {
  cursor = 0,
  pageSize = SEARCH_PAGE_SIZE,
  timeoutMs = 30000
} = {}) {
  const SOURCEGRAPH_BASE = 'https://sourcegraph.com';
  const REPO = 'github.com/CVEProject/cvelistV5';
  const CVE_RE = /CVE-\d{4}-\d{4,7}/;              // CVE-ID pattern in filenames
  const needed = cursor + pageSize;
  const limit = Math.max(pageSize, needed || pageSize);

  // Build a Sourcegraph query:
  // - repo: restricts to the CVE repo
  // - file:\.json$ restricts to JSON files
  // - content:"..." searches literal text in file contents (avoids query-token confusion)
  // - select:file converts results to unique file hits (not individual line matches)
  // - count:all asks the backend not to stop early
  // Docs: stream endpoint + SSE events; query language (file:, select:, count:)
  // https://sourcegraph.com/.api/search/stream  (see citations below)

  searchText = searchText.replace(/[\u201C\u201D\u201E\u201F\u275D\u275E\u301D\u301E\u301F]/g, '"').trim();
  
  const q = [
    `repo:^${REPO}$`,
    `file:\\.json$`,
    `content:${searchText}`,
    `select:file`,
    `count:${limit}`
  ].join(' ');

  const params = new URLSearchParams({
    q,
    v: 'V3',            // query version
    t: 'keyword'       // pattern type (aka "keyword/standard" search)
  });

  const url = `${SOURCEGRAPH_BASE}/.api/search/stream?${params.toString()}`;

  return new Promise((resolve, reject) => {
    const results = [];
    const seenPaths = new Set();
    let done = false;

    const finalize = () => {
      // Page the accumulated results client-side
      const slice = results.slice(cursor, cursor + pageSize);
      const moreExpected = !done || results.length > cursor + pageSize;
      resolve({
        items: slice,
        nextCursor: moreExpected ? cursor + slice.length : null,
        totalSoFar: results.length,
        done
      });
    };

    // Safety timeout (in case the stream never ends)
    const timeout = setTimeout(() => {
      try { es.close(); } catch {}
      done = true;
      finalize();
    }, timeoutMs);

    // Start SSE stream
    const es = new EventSource(url, { withCredentials: false });

    es.addEventListener('matches', (evt) => {
      // Each "matches" event contains an array of match objects.
      // With `select:file`, each object corresponds to a unique file result.
      const batch = JSON.parse(evt.data);
      for (const m of batch) {
        const path = m.path; // Works for both content/path match objects
        if (!path) continue;
        if (!path.endsWith('.json')) continue;

        const mCve = path.match(CVE_RE);
        if (!mCve) continue;

        if (!seenPaths.has(path)) {
          seenPaths.add(path);
            //  const repo = m.repository || REPO;
            //   const blobUrl = `${SOURCEGRAPH_BASE}/${encodeURIComponent(repo)}/-/blob/${path}`;
            //  const ghOwnerRepo = repo.replace(/^github\.com\//, '');
            //  const rawUrl = `https://raw.githubusercontent.com/${ghOwnerRepo}/HEAD/${path}`;

          results.push(mCve[0]);
          /*results.push({
            cveId: mCve[0],
            path,
            blobUrl,
            rawUrl
          });*/
        }
      }

      // If we have enough to serve this page, we can stop early to save bandwidth.
      if (results.length >= needed) {
        clearTimeout(timeout);
        try { es.close(); } catch {}
        done = false; // stream ended early by us; more could exist
        finalize();
      }
    });

    es.addEventListener('progress', (evt) => {
      const p = JSON.parse(evt.data);
      if (p.done) {
        clearTimeout(timeout);
        try { es.close(); } catch {}
        done = true;
        finalize();
      }
    });

    es.addEventListener('alert', (evt) => {
      // Non-fatal warnings/info; log to console for visibility.
      try {
        const alert = JSON.parse(evt.data);
        console.warn('Sourcegraph alert:', alert);
      } catch {}
    });

    es.addEventListener('error', (err) => {
      clearTimeout(timeout);
      try { es.close(); } catch {}
      // If we already have enough to serve the requested page, return what we have.
      if (results.length >= cursor) {
        done = true;
        finalize();
      } else {
        reject(new Error('Stream error from Sourcegraph'));
      }
    });

    es.addEventListener('done', () => {
      clearTimeout(timeout);
      try { es.close(); } catch {}
      done = true;
      finalize();
    });
  });
}

function resetSort(table){
  Array.from(table.tHead.rows[0].children).forEach(t=>t.removeAttribute('data-sort'));
}
var listPosition = 0;
document.addEventListener('DOMContentLoaded', () => {
 /* var tables = document.getElementsByClassName('sortable');
  for (let i = 0; i < tables.length; i++) {
    var table = tables[i];

      if (!table) return;

  // Function to get the cell value for comparison
  const getCellValue = (tr, colIndex) => {
    const cell = tr.children[colIndex];
    // (1) Use data-sort attribute, else cell content
    return cell.getAttribute('data-val') || cell.textContent;
  };

  // Function to compare two values
  const comparer = (idx, dataType, asc) => (a, b) => {
    let v1 = getCellValue(asc ? a : b, idx);
    let v2 = getCellValue(asc ? b : a, idx);

    // (2) Distinguish numbers and strings based on data-type
    if (dataType == 'number') {
      // Use parseFloat for numerical comparison
      v1 = parseFloat(v1.replace(/[^0-9.-]/g, '')); // Clean up (e.g., remove commas)
      v2 = parseFloat(v2.replace(/[^0-9.-]/g, ''));
      return v1 - v2;
    }

    // Default to string comparison (case-insensitive)
    return v1.toString().toLowerCase().localeCompare(v2.toString().toLowerCase());
  };

  // Attach click listener to all table headers (TH)
  Array.from(table.tHead.rows[0].children).forEach((th, index) => {
    th.addEventListener('click', () => {
      const tbody = table.tBodies[0];
      const dataType = th.getAttribute('data-type') || 'string';
      
      // Determine the current sort direction and toggle it
      let sortDir = th.getAttribute('data-sort') == 'desc' ? 'asc' : 'desc';

      // Remove sort direction indicators from all other headers
      Array.from(th.parentNode.children).forEach(h => h.removeAttribute('data-sort'));

      // Set the new sort direction indicator on the clicked header
      // Show sort direction indicators
      th.setAttribute('data-sort', sortDir);

      // Get the rows and sort them
      Array.from(tbody.querySelectorAll('tr'))
        .sort(comparer(index, dataType, sortDir == 'asc'))
        .forEach(tr => tbody.appendChild(tr)); // Re-append rows to re-order the table
    });
  });
}*/
  var backButton = document.getElementById('backButton');
  if (backButton) {
    backButton.addEventListener('click', () => {
        document.location.hash = '';
      showListPanel();
    });
  }
  setupSplitterResize();
});

const cvssSeverity = score => {
  const s = Number(score);
  if (!Number.isFinite(s) || s < 0 || s > 10) return '';
  return s === 0 ? 'NONE' : s <= 3.9 ? 'LOW' : s <= 6.9 ? 'MEDIUM' : s <= 8.9 ? 'HIGH' : 'CRITICAL';
};

// --- 1. DEFINE YOUR 5 COLORS AND STOPS ---
// The colors MUST be in RGB format for the math to work.
const stops = [
  { pos: 0,  color: { r: 102,   g: 153,   b: 0 } }, // Green
  { pos: 2,  color: { r: 202,   g: 211, b: 29 } }, // Cyan
  { pos: 5,  color: { r: 255,   g: 213, b: 28 } },   // Green
  { pos: 8,  color: { r: 242, g: 145, b: 0 } },   // Yellow
  { pos: 10, color: { r: 204, g: 1,   b: 25 } }    // Red
];

/**
 * Linearly interpolates between two numbers.
 * @param {number} a - The start value.
 * @param {number} b - The end value.
 *param {number} t - The percentage (0.0 to 1.0).
 * @returns {number}
 */
function lerp(a, b, t) {
  return a + (b - a) * t;
}

/**
 * Gets the interpolated color for a given value on the gradient scale.
 * @param {number} value - The input number (e.g., 1 to 10).
 * @param {Array} stops - The array of gradient stops.
 * @returns {string} - A CSS 'rgb(r, g, b)' string.
 */
function getGradientColor(value) {
  // --- Handle edge cases ---
  if (value <= stops[0].pos) {
    const { r, g, b } = stops[0].color;
    return `rgb(${r}, ${g}, ${b})`;
  }
  if (value >= stops[stops.length - 1].pos) {
    const { r, g, b } = stops[stops.length - 1].color;
    return `rgb(${r}, ${g}, ${b})`;
  }

  // --- Find the two stops the value is between ---
  let stop1 = stops[0];
  let stop2 = stops[1];
  for (let i = 1; i < stops.length; i++) {
    if (value <= stops[i].pos) {
      stop1 = stops[i - 1];
      stop2 = stops[i];
      break;
    }
  }

  // --- 3. Calculate Percentage (t) ---
  // How far is the value between stop1 and stop2?
  const t = (value - stop1.pos) / (stop2.pos - stop1.pos);

  // --- 4. Mix Colors (Interpolate R, G, and B) ---
  const r = Math.round(lerp(stop1.color.r, stop2.color.r, t));
  const g = Math.round(lerp(stop1.color.g, stop2.color.g, t));
  const b = Math.round(lerp(stop1.color.b, stop2.color.b, t));

  return `rgb(${r}, ${g}, ${b})`;
}

addEventListener("popstate", (event) => {
    if(event.state)
        if(event.state.text) {
            document.getElementById("q").value = event.state.text
            getCVEs(event.state.text);
    } else {
        if(event.state.cves) {
            document.getElementById("q").value = event.state.cves
            getCVEs(event.state.cves);
        }
    }
})

window.addEventListener('DOMContentLoaded', initThemeToggle);
function initThemeToggle() {
    const toggle = document.getElementById('theme-toggle');
    toggle.checked = localStorage.getItem('dark-mode') === 'true';
    document.body.setAttribute('data-theme', toggle.checked ? 'dark' : 'light');
    toggle.addEventListener('change', () => {
        localStorage.setItem('dark-mode', toggle.checked);
        document.body.setAttribute('data-theme', (toggle.checked ? 'dark' : 'light'));
    });
}

icon = {
    'unsupported-when-assigned': 'vgi-no gray',
    'exclusively-hosted-service': 'vgi-cloud NONE',
    'x_known-exploited-vulnerability': 'vgi-bomb CRITICAL',
    'disputed': 'vgi-what gray'
}
