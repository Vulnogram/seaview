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
        cnaSearchID = match[2] || match[1];
        return await fetchCnaCveList(normalizeShortName(cnaSearchID));
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
                    res.jsonURL = jsonURL;
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
        "title": "Attack Vector",
        "infoText": "This metric reflects the context by which vulnerability exploitation is possible. This metric value (and consequently the resulting severity) will be larger the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable system. The assumption is that the number of potential attackers for a vulnerability that could be exploited from across a network is larger than the number of potential attackers that could exploit a vulnerability requiring physical access to a device, and therefore warrants a greater severity.",
        "PHYSICAL": {
            "title": "Physical",
            "infoText": "The attack requires the attacker to physically touch or manipulate the vulnerable system. Physical interaction may be brief (e.g., evil maid attack) or persistent.",
            "icon": "cvss-physical"
        },
        "LOCAL": {
            "title": "Local",
            "infoText": "The vulnerable system is not bound to the network stack and the attacker\u2019s path is via read/write/execute capabilities. Either the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or through terminal emulation (e.g., SSH); or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., using social engineering techniques to trick a legitimate user into opening a malicious document).",
            "icon": "cvss-user"
        },
        "ADJACENT": {
            "title": "Adjacent",
            "infoText": "The vulnerable system is bound to a protocol stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared proximity (e.g., Bluetooth, NFC, or IEEE 802.11) or logical network (e.g., local IP subnet), or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN within an administrative network zone).",
            "icon": "cvss-adj"
        },
        "NETWORK": {
            "class":"bad",
            "title": "Network",
            "infoText": "The vulnerable system is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. Such a vulnerability is often termed \u201cremotely exploitable\u201d and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers).",
            "icon": "cvss-net"
        }
    },
    "attackComplexity": {
        "title": "Attack Complexity",
        "infoText": "This metric captures measurable actions that must be taken by the attacker to actively evade or circumvent existing built-in security-enhancing conditions in order to obtain a working exploit. These are conditions whose primary purpose is to increase security and/or increase exploit engineering complexity. A vulnerability exploitable without a target-specific variable has a lower complexity than a vulnerability that would require non-trivial customization. This metric is meant to capture security mechanisms utilized by the vulnerable system.",
        "HIGH": {
            "title": "High",
            "infoText": "The successful attack depends on the evasion or circumvention of security-enhancing techniques in place that would otherwise hinder the attack. These include: Evasion of exploit mitigation techniques, for example, circumvention of address space randomization (ASLR) or data execution prevention (DEP) must be performed for the attack to be successful; Obtaining target-specific secrets. The attacker must gather some target-specific secret before the attack can be successful. A secret is any piece of information that cannot be obtained through any amount of reconnaissance. To obtain the secret the attacker must perform additional attacks or break otherwise secure measures (e.g. knowledge of a secret key may be needed to break a crypto channel). This operation must be performed for each attacked target.",
            "icon": "rocket"
        },
        "LOW": {
            "title": "Low",
            "infoText": "The attacker must take no measurable action to exploit the vulnerability. The attack requires no target-specific circumvention to exploit the vulnerability. An attacker can expect repeatable success against the vulnerable system.",
            "icon": "paper-plane"
        }
    },
    "attackRequirements": {
        "title": "Attack Requirements",
        "infoText": "This metric captures the prerequisite deployment and execution conditions or variables of the vulnerable system that enable the attack. These differ from security-enhancing techniques/technologies (ref Attack Complexity) as the primary purpose of these conditions is not to explicitly mitigate attacks, but rather, emerge naturally as a consequence of the deployment and execution of the vulnerable system.",
        "PRESENT": {
            "title": "Present",
            "infoText": "The successful attack depends on the presence of specific deployment and execution conditions of the vulnerable system that enable the attack. These include: a race condition must be won to successfully exploit the vulnerability (the successfulness of the attack is conditioned on execution conditions that are not under full control of the attacker, or the attack may need to be launched multiple times against a single target before being successful); the attacker must inject themselves into the logical network path between the target and the resource requested by the victim (e.g. vulnerabilities requiring an on-path attacker).",
            "icon": "cvss-required"
        },
        "NONE": {
            "title": "None",
            "infoText": "The successful attack does not depend on the deployment and execution conditions of the vulnerable system. The attacker can expect to be able to reach the vulnerability and execute the exploit under all or most instances of the vulnerability.",
            "icon": "cvss-direct"
        }
    },
    "privilegesRequired": {
        "title": "Privileges Required",
        "infoText": "This metric describes the level of privileges an attacker must possess prior to successfully exploiting the vulnerability. The method by which the attacker obtains privileged credentials prior to the attack (e.g., free trial accounts), is outside the scope of this metric. Generally, self-service provisioned accounts do not constitute a privilege requirement if the attacker can grant themselves privileges as part of the attack.",
        "HIGH": {
            "title": "High",
            "infoText": "The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable system allowing full access to the vulnerable system\u2019s settings and files.",
            "icon": "king"
        },
        "LOW": {
            "title": "Low",
            "infoText": "The attacker requires privileges that provide basic capabilities that are typically limited to settings and resources owned by a single low-privileged user. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.",
            "icon": "pawn"
        },
        "NONE": {
            "title": "None",
            "infoText": "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files of the vulnerable system to carry out an attack.",
            "icon": "thief"
        }
    },
    "userInteraction": {
        "title": "User Interaction",
        "infoText": "This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable system. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner.",
        "ACTIVE": {
            "title": "Active",
            "infoText": "Successful exploitation of this vulnerability requires a targeted user to perform specific, conscious interactions with the vulnerable system and the attacker\u2019s payload, or the user\u2019s interactions would actively subvert protection mechanisms which would lead to exploitation of the vulnerability.",
            "icon": "alert"
        },
        "PASSIVE": {
            "title": "Passive",
            "infoText": "Successful exploitation of this vulnerability requires limited interaction by the targeted user with the vulnerable system and the attacker\u2019s payload. These interactions would be considered involuntary and do not require that the user actively subvert protections built into the vulnerable system.",
            "icon": "eye-half"
        },
        "NONE": {
            "title": "None",
            "infoText": "The vulnerable system can be exploited without interaction from any human user, other than the attacker.",
            "icon": "cvss-direct"
        }
    },
    "confidentialityImpact": {
        "title": "Confidentiality",
        "infoText": "This metric measures the impact to the confidentiality.",
        "NONE": {
            "title": "None",
            "infoText": "There is no loss of confidentiality.",
            "icon": "eye-close"
        },
        "LOW": {
            "title": "Low",
            "infoText": "There is some loss of confidentiality.",
            "icon": "eye-half"
        },
        "HIGH": {
            "class":"bad",
            "title": "High",
            "infoText": "There is a total loss of confidentiality.",
            "icon": "eye"
        }
    },
    "vulnConfidentialityImpact": {
        "title": "Product Confidentiality",
        "infoText": "This metric measures the impact to the confidentiality of the information managed by the VULNERABLE SYSTEM due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.",
        "NONE": {
            "title": "None",
            "infoText": "There is no loss of confidentiality within the Vulnerable System.",
            "icon": "eye-close"
        },
        "LOW": {
            "title": "Low",
            "infoText": "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the Vulnerable System.",
            "icon": "eye-half"
        },
        "HIGH": {
            "class":"bad",
            "title": "High",
            "infoText": "There is a total loss of confidentiality, resulting in all information within the Vulnerable System being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server.",
            "icon": "eye"
        }
    },
    "subConfidentialityImpact": {
        "title": "Subsequent Confidentiality",
        "infoText": "This metric measures the impact to the confidentiality of the information managed by the SUBSEQUENT SYSTEM due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.",
        "NONE": {
            "title": "None",
            "infoText": "There is no loss of confidentiality within the Subsequent System or all confidentiality impact is constrained to the Vulnerable System.",
            "icon": "eye-close"
        },
        "LOW": {
            "title": "Low",
            "infoText": "There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the Subsequent System.",
            "icon": "eye-half"
        },
        "HIGH": {
            "class":"bad",
             "title": "High",
            "infoText": "There is a total loss of confidentiality, resulting in all resources within the Subsequent System being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact. For example, an attacker steals the administrator's password, or private encryption keys of a web server.",
            "icon": "eye"
        }
    },
    "integrityImpact": {
        "title": "Integrity",
        "infoText": "This metric measures the impact to integrity of a successfully exploited vulnerability.",
        "NONE": {
            "title": "None",
            "infoText": "There is no loss of integrity.",
            "icon": "box"
        },
        "LOW": {
            "title": "Low",
            "infoText": "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact.",
            "icon": "box-low"
        },
        "HIGH": {
           "class":"bad",
             "title": "High",
            "infoText": "There is a total loss of integrity, or a complete loss of protection.",
            "icon": "box-high"
        }
    },
    "vulnIntegrityImpact": {
        "title": "Product Integrity",
        "infoText": "This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. Integrity of the VULNERABLE SYSTEM is impacted when an attacker makes unauthorized modification of system data. Integrity is also impacted when a system user can repudiate critical actions taken in the context of the system (e.g. due to insufficient logging).",
        "NONE": {
            "title": "None",
            "infoText": "There is no loss of integrity within the Vulnerable System.",
            "icon": "box"
        },
        "LOW": {
            "title": "Low",
            "infoText": "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Vulnerable System.",
            "icon": "box-low"
        },
        "HIGH": {
           "class":"bad",
             "title": "High",
            "infoText": "There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the vulnerable system. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the vulnerable system.",
            "icon": "box-high"
        }
    },
    "subIntegrityImpact": {
        "title": "Subsequent Integrity",
        "infoText": "This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. Integrity of the SUBSEQUENT SYSTEM is impacted when an attacker makes unauthorized modification of system data. Integrity is also impacted when a system user can repudiate critical actions taken in the context of the system (e.g. due to insufficient logging).",
        "NONE": {
            "title": "None",
            "infoText": "There is no loss of integrity within the Subsequent System or all integrity impact is constrained to the Vulnerable System.",
            "icon": "box"
        },
        "LOW": {
            "title": "Low",
            "infoText": "Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact to the Subsequent System.",
            "icon": "box-low"
        },
        "HIGH": {
           "class":"bad",
             "title": "High",
            "infoText": "There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the Subsequent System. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the Subsequent System.",
            "icon": "box-high"
        }
    },
    "availabilityImpact": {
        "title": "Availability",
        "infoText": "This metric measures the impact to the availability.",
        "NONE": {
            "title": "None",
            "infoText": "There is no impact to availability.",
            "icon": "signal"
        },
        "LOW": {
            "title": "Low",
            "infoText": "Performance is reduced or there are interruptions in resource availability.",
            "icon": "signal-2"
        },
        "HIGH": {
           "class":"bad",
             "title": "High",
            "infoText": "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources.",
            "icon": "signal-1"
        }
    },
    "vulnAvailabilityImpact": {
        "title": "Product Availability",
        "infoText": "This metric measures the impact to the availability of the VULNERABLE SYSTEM resulting from a successfully exploited vulnerability. While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of data (e.g., information, files) used by the system, this metric refers to the loss of availability of the impacted system itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of a system.",
        "NONE": {
            "title": "None",
            "infoText": "There is no impact to availability within the Vulnerable System.",
            "icon": "signal"
        },
        "LOW": {
            "title": "Low",
            "infoText": "Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the Vulnerable System are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Vulnerable System.",
            "icon": "signal-2"
        },
        "HIGH": {
           "class":"bad",
             "title": "High",
            "infoText": "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Vulnerable System; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Vulnerable System (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).",
            "icon": "signal-1"
        }
    },
    "subAvailabilityImpact": {
        "title": "Subsequent System Availability",
        "infoText": "This metric measures the impact to the availability of the SUBSEQUENT SYSTEM resulting from a successfully exploited vulnerability. While the Confidentiality and Integrity impact metrics apply to the loss of confidentiality or integrity of data (e.g., information, files) used by the system, this metric refers to the loss of availability of the impacted system itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of a system.",
        "NONE": {
            "title": "None",
            "infoText": "There is no impact to availability within the Subsequent System or all availability impact is constrained to the Vulnerable System.",
            "icon": "signal"
        },
        "LOW": {
            "title": "Low",
            "infoText": "Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the Subsequent System are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the Subsequent System.",
            "icon": "signal-2"
        },
        "HIGH": {
           "class":"bad",
             "title": "High",
            "infoText": "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources in the Subsequent System; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the Subsequent System (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).",
            "icon": "signal-1"
        }
    },
    "scope": {
        "title": "Scope Change",
        "infoText": "",
        "CHANGED": {
            "icon": "cvss-scope-change",
            "title": "Changed",
            "infoText": "Worst: An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.",
        },
        "UNCHANGED": {
            "icon": "cvss-direct",
            "title": "Unchanged",
            "infoText": "Bad: An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority."
        } 
    },
    "exploitMaturity": {
        "title": "Exploit Maturity",
        "infoText": "This metric measures the likelihood of the vulnerability being attacked, and is based on the current state of exploit techniques, exploit code availability, or active, \u201cin-the-wild\u201d exploitation.",
        "UNREPORTED": {
            "title": "Unreported",
            "infoText": "Based on available threat intelligence each of the following must apply:\nNo knowledge of publicly available proof-of-concept exploit code No knowledge of reported attempts to exploit this vulnerability\nNo knowledge of publicly available solutions used to simplify attempts to exploit the vulnerability (i.e., neither the \u201cPOC\u201d nor \u201cAttacked\u201d values apply)",
            "icon": "what"
        },
        "PROOF_OF_CONCEPT": {
            "title": "Published Proof-of-Concept",
            "infoText": "Based on available threat intelligence each of the following must apply:\nProof-of-concept exploit code is publicly available\nNo knowledge of reported attempts to exploit this vulnerability\nNo knowledge of publicly available solutions used to simplify attempts to exploit the vulnerability",
            "icon": "text"
        },
        "ATTACKED": {
            "title": "Attacked",
            "infoText": "Based on available threat intelligence each of the following must apply:\nNo knowledge of publicly available proof-of-concept exploit code No knowledge of reported attempts to exploit this vulnerability\nNo knowledge of publicly available solutions used to simplify attempts to exploit the vulnerability (i.e., neither the \u201cPOC\u201d nor \u201cAttacked\u201d values apply)",
            "icon": "bomb"
        },
        "NOT_DEFINED": {
            "title": "Not Defined",
            "infoText": "Reliable threat intelligence is not available to determine Exploit Maturity characteristics.",
            "icon": "what"
        }
    },
    "Safety": {
        "title": "Safety Impact",
        "infoText": "When a system does have an intended use or fitness of purpose aligned to safety, it is possible that exploiting a vulnerability within that system may have Safety impact which can be represented in the Supplemental Metrics group. Lack of a Safety metric value being supplied does NOT mean that there may not be any Safety-related impacts.",
        "NOT_DEFINED": {
            "title": "Not defined",
            "infoText": "The metric has not been evaluated.",
            "icon": "what"
        },
        "NEGLIGIBLE": {
            "title": "Negligible",
            "infoText": "Consequences of the vulnerability meet definition of IEC 61508 consequence category \"negligible.\"",
            "icon": "bandage"
        },
        "PRESENT": {
            "title": "Present",
            "infoText": "Consequences of the vulnerability meet definition of IEC 61508 consequence categories of \"marginal,\" \"critical,\" or \"catastrophic.\"",
            "icon": "ambulance"
        }
    },
    "Automatable": {
        "title": "Automatable attack",
        "infoText": "The \u201c The \u201cAutomatable\u201d metric captures the answer to the question \u201dCan an attacker automate exploitation events for this vulnerability across multiple targets?\u201d based on steps 1-4 of the kill chain [Hutchins et al., 2011]. These steps are reconnaissance, weaponization, delivery, and exploitation.",
        "NOT_DEFINED": {
            "title": "Not defined",
            "infoText": "The metric has not been evaluated.",
            "icon": "what"
        },
        "NO": {
            "title": "No",
            "infoText": "Attackers cannot reliably automate all 4 steps of the kill chain for this vulnerability for some reason. These steps are reconnaissance, weaponization, delivery, and exploitation.",
            "icon": "manual"
        },
        "YES": {
            "title": "Yes",
            "infoText": "Attackers can reliably automate all 4 steps of the kill chain. These steps are reconnaissance, weaponization, delivery, and exploitation (e.g., the vulnerability is \u201cwormable\u201d).",
            "icon": "cog"
        }
    },
    "Recovery": {
        "title": "Recovery",
        "infoText": "Recovery describes the resilience of a system to recover services, in terms of performance and availability, after an attack has been performed.",
        "NOT_DEFINED": {
            "title": "Not defined",
            "infoText": "The metric has not been evaluated.",
            "icon": "what"
        },
        "AUTOMATIC": {
            "title": "Automatic",
            "infoText": "The system recovers services automatically after an attack has been performed.",
            "icon": "reuse"
        },
        "USER": {
            "title": "User",
            "infoText": "The system requires manual intervention by the user to recover services, after an attack has been performed.",
            "icon": "manual"
        },
        "IRRECOVERABLE": {
            "title": "Irrecoverable",
            "infoText": "The system services are irrecoverable by the user, after an attack has been performed.",
            "icon": "bomb"
        }
    },
    "valueDensity": {
        "title": "Value Density",
        "infoText": "Value Density describes the resources that the attacker will gain control over with a single exploitation event.",
        "NOT_DEFINED": {
            "title": "Not defined",
            "infoText": "The metric has not been evaluated.",
            "icon": "what"
        },
        "DIFFUSE": {
            "title": "Diffuse",
            "infoText": "The vulnerable system has limited resources. That is, the resources that the attacker will gain control over with a single exploitation event are relatively small. An example of Diffuse (think: limited) Value Density would be an attack on a single email client vulnerability.",
            "icon": "diffuse"
        },
        "CONCENTRATED": {
            "title": "Concentrated",
            "infoText": "The vulnerable system is rich in resources. Heuristically, such systems are often the direct responsibility of \u201csystem operators\u201d rather than users. An example of Concentrated (think: broad) Value Density would be an attack on a central email server.",
            "icon": "box"
        }
    },
    "vulnerabilityResponseEffort": {
        "title": "Vulnerability Response Effort",
        "infoText": "The intention of the Vulnerability Response Effort metric is to provide supplemental information on how difficult it is for consumers to provide an initial response to the impact of vulnerabilities for deployed products and services in their infrastructure. The consumer can then take this additional information on effort required into consideration when applying mitigations and/or scheduling remediation.",
        "NOT_DEFINED": {
            "title": "Not defined",
            "infoText": "The metric has not been evaluated.",
            "icon": "what"
        },
        "LOW": {
            "title": "Low",
            "infoText": "The effort required to respond to a vulnerability is low/trivial. Examples include: communication on better documentation, configuration workarounds, or guidance from the vendor that does not require an immediate update, upgrade, or replacement by the consuming entity, such as firewall filter configuration.",
            "icon": "feather"
        },
        "MODERATE": {
            "title": "Moderate",
            "infoText": "The actions required to respond to a vulnerability require some effort on behalf of the consumer and could cause minimal service impact to implement. Examples include: simple remote update, disabling of a subsystem, or a low-touch software upgrade such as a driver update.",
            "icon": "mop"
        },
        "HIGH": {
            "title": "High",
            "infoText": "The actions required to respond to a vulnerability are significant and/or difficult, and may possibly lead to an extended, scheduled service impact.  This would need to be considered for scheduling purposes including honoring any embargo on deployment of the selected response. Alternatively, response to the vulnerability in the field is not possible remotely. The only resolution to the vulnerability involves physical replacement (e.g. units deployed would have to be recalled for a depot level repair or replacement). Examples include: a highly privileged driver update, microcode or UEFI BIOS updates, or software upgrades requiring careful analysis and understanding of any potential infrastructure impact before implementation. A UEFI BIOS update that impacts Trusted Platform Module (TPM) attestation without impacting disk encryption software such as Bit locker is a good recent example. Irreparable failures such as non-bootable flash subsystems, failed disks or solid-state drives (SSD), bad memory modules, network devices, or other non-recoverable under warranty hardware, should also be scored as having a High effort.",
            "icon": "tanker"
        }
    },
    "providerUrgency": {
        "title": "Urgency",
        "infoText": "To facilitate a standardized method to incorporate additional provider-supplied assessment, an optional \u201cpass-through\u201d Supplemental Metric called Provider Urgency is available. Note: While any assessment provider along the product supply chain may provide a Provider Urgency rating. The Penultimate Product Provider (PPP) is best positioned to provide a direct assessment of Provider Urgency.",
        "NOT_DEFINED": {
            "title": "Not defined",
            "infoText": "The metric has not been evaluated.",
            "icon": "what"
        },
        "CLEAR": {
            "title": "Informational",
            "infoText": "Provider has assessed the impact of this vulnerability as having no urgency (Informational).",
            "icon": "info"
        },
        "GREEN": {
            "title": "Reduced",
            "infoText": "Provider has assessed the impact of this vulnerability as having a reduced urgency.",
            "icon": "sit"
        },
        "AMBER": {
            "title": "Normal",
            "infoText": "Provider has assessed the impact of this vulnerability as having a moderate urgency.",
            "icon": "walk"
        },
        "RED": {
            "title": "Highest",
            "infoText": "Provider has assessed the impact of this vulnerability as having the highest urgency.",
            "icon": "run"
        }
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
function normalizeShortName(shortName) {
    if (!shortName) return null;
    return String(shortName).trim().toLowerCase().replace(/\s+/g, '_');
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
    con.shortName = CDM.assignerShortName || PMD.shortName;
    con.url = cna[con.shortName] ? cna[con.shortName].i : false;
    if(!con.url) {
        var nsn = normalizeShortName(con.shortName);
        con.url = cna[nsn] ? cna[nsn].i : false;
    }
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
        if(!adp.url) {
            var nsn = normalizeShortName(adp.shortName);
            adp.url = cna[nsn] ? cna[nsn].i : false;
        }
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
