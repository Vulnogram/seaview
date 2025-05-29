function pug_attr(t,e,n,r){if(!1===e||null==e||!e&&("class"===t||"style"===t))return"";if(!0===e)return" "+(r?t:t+'="'+t+'"');var f=typeof e;return"object"!==f&&"function"!==f||"function"!=typeof e.toJSON||(e=e.toJSON()),"string"==typeof e||(e=JSON.stringify(e),n||-1===e.indexOf('"'))?(n&&(e=pug_escape(e))," "+t+'="'+e+'"'):" "+t+"='"+e.replace(/'/g,"&#39;")+"'"}
function pug_classes(s,r){return Array.isArray(s)?pug_classes_array(s,r):s&&"object"==typeof s?pug_classes_object(s):s||""}
function pug_classes_array(r,a){for(var s,e="",u="",c=Array.isArray(a),g=0;g<r.length;g++)(s=pug_classes(r[g]))&&(c&&a[g]&&(s=pug_escape(s)),e=e+u+s,u=" ");return e}
function pug_classes_object(r){var a="",n="";for(var o in r)o&&r[o]&&pug_has_own_property.call(r,o)&&(a=a+n+o,n=" ");return a}
function pug_escape(e){var a=""+e,t=pug_match_html.exec(a);if(!t)return e;var r,c,n,s="";for(r=t.index,c=0;r<a.length;r++){switch(a.charCodeAt(r)){case 34:n="&quot;";break;case 38:n="&amp;";break;case 60:n="&lt;";break;case 62:n="&gt;";break;default:continue}c!==r&&(s+=a.substring(c,r)),c=r+1,s+=n}return c!==r?s+a.substring(c,r):s}
var pug_has_own_property=Object.prototype.hasOwnProperty;
var pug_match_html=/["&<>]/;function cve(locals) {var pug_html = "", pug_mixins = {}, pug_interp;;
    var locals_for_with = (locals || {});
    
    (function (Array, Date, JSON, Object, URL, cna, d, encodeURIComponent, isNaN, nonSpec, renderTemplate, statusFunction) {
      var nonSpec = ['baseScore', 'version', 'vectorString', 'baseSeverity', 'scenarios']
pug_mixins["cvssList"] = pug_interp = function(cvssList){
var block = (this && this.block), attributes = (this && this.attributes) || {};
if (cvssList) {
// iterate cvssList
;(function(){
  var $$obj = cvssList;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var cvss = $$obj[i];
pug_html = pug_html + "\u003Cdetails class=\"popup\"\u003E\u003Csummary" + (pug_attr("class", pug_classes(["lbl","rnd","tag","CVSS",cvss.baseSeverity ? cvss.baseSeverity : 'gray'], [false,false,false,false,true]), false, false)) + "\u003E" + (pug_escape(null == (pug_interp = cvss.baseSeverity) ? "" : pug_interp)) + "· \u003Csup\u003E" + (pug_escape(null == (pug_interp = cvss.baseScore) ? "" : pug_interp)) + "\u003C\u002Fsup\u003E⁄10\u003C\u002Fsummary\u003E\u003Cdiv class=\"pop wht rnd shd pad bor\"\u003E";
if (cvss.scenarios && cvss.scenarios.length > 0) {
pug_html = pug_html + "\u003Cb\u003EScenarios:\u003C\u002Fb\u003E\u003Cul\u003E";
// iterate cvss.scenarios
;(function(){
  var $$obj = cvss.scenarios;
  if ('number' == typeof $$obj.length) {
      for (var pug_index1 = 0, $$l = $$obj.length; pug_index1 < $$l; pug_index1++) {
        var s = $$obj[pug_index1];
pug_html = pug_html + "\u003Cli\u003E" + (pug_escape(null == (pug_interp = s.value) ? "" : pug_interp)) + "\u003C\u002Fli\u003E";
      }
  } else {
    var $$l = 0;
    for (var pug_index1 in $$obj) {
      $$l++;
      var s = $$obj[pug_index1];
pug_html = pug_html + "\u003Cli\u003E" + (pug_escape(null == (pug_interp = s.value) ? "" : pug_interp)) + "\u003C\u002Fli\u003E";
    }
  }
}).call(this);

pug_html = pug_html + "\u003C\u002Ful\u003E";
}
// iterate cvss
;(function(){
  var $$obj = cvss;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var x = $$obj[i];
if (!nonSpec.includes(i)) {
pug_html = pug_html + "\u003Cdiv\u003E" + (pug_escape(null == (pug_interp = i) ? "" : pug_interp)) + ":  \u003Cb\u003E" + (pug_escape(null == (pug_interp = x) ? "" : pug_interp)) + "\u003C\u002Fb\u003E\u003C\u002Fdiv\u003E";
}
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var x = $$obj[i];
if (!nonSpec.includes(i)) {
pug_html = pug_html + "\u003Cdiv\u003E" + (pug_escape(null == (pug_interp = i) ? "" : pug_interp)) + ":  \u003Cb\u003E" + (pug_escape(null == (pug_interp = x) ? "" : pug_interp)) + "\u003C\u002Fb\u003E\u003C\u002Fdiv\u003E";
}
    }
  }
}).call(this);

pug_html = pug_html + "\u003Cdiv\u003E";
if (cvss.version >= "4") {
pug_html = pug_html + "\u003Ca" + (" class=\"vgi-ext\""+pug_attr("href", "https://www.first.org/cvss/calculator/4-0#" + cvss.vectorString, true, false)) + "\u003EOpen CVSS Calc\u003C\u002Fa\u003E";
}
else
if (cvss.version >= "3") {
pug_html = pug_html + "\u003Ca" + (" class=\"vgi-ext\""+pug_attr("href", "https://cvssjs.github.io/#" + cvss.vectorString, true, false)) + "\u003EOpen CVSS Calc\u003C\u002Fa\u003E";
}
else {
pug_html = pug_html + "\u003Ca" + (" class=\"vgi-ext\""+pug_attr("href", 'https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector='+cvss.vectorString, true, false)) + "\u003EOpen CVSS Calc\u003C\u002Fa\u003E";
}
pug_html = pug_html + "\u003C\u002Fdiv\u003E\u003C\u002Fdiv\u003E\u003C\u002Fdetails\u003E";
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var cvss = $$obj[i];
pug_html = pug_html + "\u003Cdetails class=\"popup\"\u003E\u003Csummary" + (pug_attr("class", pug_classes(["lbl","rnd","tag","CVSS",cvss.baseSeverity ? cvss.baseSeverity : 'gray'], [false,false,false,false,true]), false, false)) + "\u003E" + (pug_escape(null == (pug_interp = cvss.baseSeverity) ? "" : pug_interp)) + "· \u003Csup\u003E" + (pug_escape(null == (pug_interp = cvss.baseScore) ? "" : pug_interp)) + "\u003C\u002Fsup\u003E⁄10\u003C\u002Fsummary\u003E\u003Cdiv class=\"pop wht rnd shd pad bor\"\u003E";
if (cvss.scenarios && cvss.scenarios.length > 0) {
pug_html = pug_html + "\u003Cb\u003EScenarios:\u003C\u002Fb\u003E\u003Cul\u003E";
// iterate cvss.scenarios
;(function(){
  var $$obj = cvss.scenarios;
  if ('number' == typeof $$obj.length) {
      for (var pug_index3 = 0, $$l = $$obj.length; pug_index3 < $$l; pug_index3++) {
        var s = $$obj[pug_index3];
pug_html = pug_html + "\u003Cli\u003E" + (pug_escape(null == (pug_interp = s.value) ? "" : pug_interp)) + "\u003C\u002Fli\u003E";
      }
  } else {
    var $$l = 0;
    for (var pug_index3 in $$obj) {
      $$l++;
      var s = $$obj[pug_index3];
pug_html = pug_html + "\u003Cli\u003E" + (pug_escape(null == (pug_interp = s.value) ? "" : pug_interp)) + "\u003C\u002Fli\u003E";
    }
  }
}).call(this);

pug_html = pug_html + "\u003C\u002Ful\u003E";
}
// iterate cvss
;(function(){
  var $$obj = cvss;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var x = $$obj[i];
if (!nonSpec.includes(i)) {
pug_html = pug_html + "\u003Cdiv\u003E" + (pug_escape(null == (pug_interp = i) ? "" : pug_interp)) + ":  \u003Cb\u003E" + (pug_escape(null == (pug_interp = x) ? "" : pug_interp)) + "\u003C\u002Fb\u003E\u003C\u002Fdiv\u003E";
}
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var x = $$obj[i];
if (!nonSpec.includes(i)) {
pug_html = pug_html + "\u003Cdiv\u003E" + (pug_escape(null == (pug_interp = i) ? "" : pug_interp)) + ":  \u003Cb\u003E" + (pug_escape(null == (pug_interp = x) ? "" : pug_interp)) + "\u003C\u002Fb\u003E\u003C\u002Fdiv\u003E";
}
    }
  }
}).call(this);

pug_html = pug_html + "\u003Cdiv\u003E";
if (cvss.version >= "4") {
pug_html = pug_html + "\u003Ca" + (" class=\"vgi-ext\""+pug_attr("href", "https://www.first.org/cvss/calculator/4-0#" + cvss.vectorString, true, false)) + "\u003EOpen CVSS Calc\u003C\u002Fa\u003E";
}
else
if (cvss.version >= "3") {
pug_html = pug_html + "\u003Ca" + (" class=\"vgi-ext\""+pug_attr("href", "https://cvssjs.github.io/#" + cvss.vectorString, true, false)) + "\u003EOpen CVSS Calc\u003C\u002Fa\u003E";
}
else {
pug_html = pug_html + "\u003Ca" + (" class=\"vgi-ext\""+pug_attr("href", 'https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector='+cvss.vectorString, true, false)) + "\u003EOpen CVSS Calc\u003C\u002Fa\u003E";
}
pug_html = pug_html + "\u003C\u002Fdiv\u003E\u003C\u002Fdiv\u003E\u003C\u002Fdetails\u003E";
    }
  }
}).call(this);

}
};
pug_mixins["statusTablev4"] = pug_interp = function(st){
var block = (this && this.block), attributes = (this && this.attributes) || {};
pug_html = pug_html + "\u003Ctable class=\"tbl gap\"\u003E\u003Ccolgroup\u003E\u003Ccol\u002F\u003E";
if (st.show.platforms) {
pug_html = pug_html + "\u003Ccol\u002F\u003E";
}
pug_html = pug_html + "\u003Ccol class=\"affectedCol\"\u002F\u003E\u003C\u002Fcolgroup\u003E\u003Cthead\u003E\u003Ctr\u003E\u003Cth\u003EProduct\u003C\u002Fth\u003E";
if (st.show.platforms) {
pug_html = pug_html + "\u003Cth\u003EPlatforms\u003C\u002Fth\u003E";
}
if (st.show.modules) {
pug_html = pug_html + "\u003Cth\u003EModules\u003C\u002Fth\u003E";
}
pug_html = pug_html + "\u003Cth\u003EAffected\u003C\u002Fth\u003E";
if (st.show.unaffected) {
pug_html = pug_html + "\u003Cth\u003EUnaffected\u003C\u002Fth\u003E";
}
if (st.show.unknown) {
pug_html = pug_html + "\u003Cth\u003EUnknown\u003C\u002Fth\u003E";
}
pug_html = pug_html + "\u003C\u002Ftr\u003E\u003C\u002Fthead\u003E\u003Ctbody\u003E";
// iterate st.cols
;(function(){
  var $$obj = st.cols;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var p = $$obj[i];
pug_html = pug_html + "\u003Ctr\u003E\u003Ctd\u003E" + (pug_escape(null == (pug_interp = p[0]) ? "" : pug_interp)) + "\u003C\u002Ftd\u003E";
if (st.show.platforms) {
pug_html = pug_html + "\u003Ctd\u003E" + (pug_escape(null == (pug_interp = p[1]) ? "" : pug_interp)) + "\u003C\u002Ftd\u003E";
}
if (st.show.modules) {
pug_html = pug_html + "\u003Ctd\u003E" + (pug_escape(null == (pug_interp = p[2]) ? "" : pug_interp)) + "\u003C\u002Ftd\u003E";
}
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](st.vals.affected[i]);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
if (st.show.unaffected) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](st.vals.unaffected[i]);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
if (st.show.unknown) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](st.vals.unknown[i]);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
pug_html = pug_html + "\u003C\u002Ftr\u003E";
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var p = $$obj[i];
pug_html = pug_html + "\u003Ctr\u003E\u003Ctd\u003E" + (pug_escape(null == (pug_interp = p[0]) ? "" : pug_interp)) + "\u003C\u002Ftd\u003E";
if (st.show.platforms) {
pug_html = pug_html + "\u003Ctd\u003E" + (pug_escape(null == (pug_interp = p[1]) ? "" : pug_interp)) + "\u003C\u002Ftd\u003E";
}
if (st.show.modules) {
pug_html = pug_html + "\u003Ctd\u003E" + (pug_escape(null == (pug_interp = p[2]) ? "" : pug_interp)) + "\u003C\u002Ftd\u003E";
}
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](st.vals.affected[i]);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
if (st.show.unaffected) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](st.vals.unaffected[i]);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
if (st.show.unknown) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](st.vals.unknown[i]);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
pug_html = pug_html + "\u003C\u002Ftr\u003E";
    }
  }
}).call(this);

pug_html = pug_html + "\u003C\u002Ftbody\u003E\u003C\u002Ftable\u003E";
};
pug_mixins["prodDetails"] = pug_interp = function(p){
var block = (this && this.block), attributes = (this && this.attributes) || {};
pug_html = pug_html + "\u003Cb class=\"vgi-package\"\u003E" + (pug_escape(null == (pug_interp = p[0]) ? "" : pug_interp)) + "\u003C\u002Fb\u003E";
if (p[2]) {
pug_html = pug_html + "\u003Cspan\u003E » " + (pug_escape(null == (pug_interp = p[2]) ? "" : pug_interp)) + "\u003C\u002Fspan\u003E";
}
if (p[1]) {
pug_html = pug_html + "\u003Ci\u003E on \u003C\u002Fi\u003E \u003Cspan class=\"vgi-stack\"\u003E" + (pug_escape(null == (pug_interp = p[1]) ? "" : pug_interp)) + "\u003C\u002Fspan\u003E";
}
if (p[3]) {
pug_html = pug_html + "\u003Cbr\u002F\u003E";
if (p[3].collectionURL) {
pug_html = pug_html + "\u003Ca" + (" class=\"vgi-package\""+pug_attr("href", p[3].collectionURL, true, false)) + "\u003Epackage repo\u003C\u002Fa\u003E";
}
if (p[3].repo) {
pug_html = pug_html + "\u003Ca" + (" class=\"vgi-ext\""+pug_attr("href", p[3].repo, true, false)) + "\u003Esource repo\u003C\u002Fa\u003E";
}
if (p[3].programFiles) {
// iterate p[3].programFiles
;(function(){
  var $$obj = p[3].programFiles;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var f = $$obj[i];
pug_html = pug_html + "\u003Cspan class=\"vgi-text\"\u003E" + (pug_escape(null == (pug_interp = f) ? "" : pug_interp)) + "\u003C\u002Fspan\u003E";
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var f = $$obj[i];
pug_html = pug_html + "\u003Cspan class=\"vgi-text\"\u003E" + (pug_escape(null == (pug_interp = f) ? "" : pug_interp)) + "\u003C\u002Fspan\u003E";
    }
  }
}).call(this);

}
if (p[3].programRoutines) {
// iterate p[3].programRoutines
;(function(){
  var $$obj = p[3].programRoutines;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var f = $$obj[i];
pug_html = pug_html + "\u003Cspan class=\"vgi-edit\"\u003E" + (pug_escape(null == (pug_interp = f.name) ? "" : pug_interp)) + "\u003C\u002Fspan\u003E";
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var f = $$obj[i];
pug_html = pug_html + "\u003Cspan class=\"vgi-edit\"\u003E" + (pug_escape(null == (pug_interp = f.name) ? "" : pug_interp)) + "\u003C\u002Fspan\u003E";
    }
  }
}).call(this);

}
}
};
pug_mixins["statusTablev5"] = pug_interp = function(st){
var block = (this && this.block), attributes = (this && this.attributes) || {};
pug_html = pug_html + "\u003Ctable class=\"tbl gap\"\u003E\u003Ccolgroup\u003E\u003Ccol\u002F\u003E\u003Ccol class=\"affectedCol\"\u002F\u003E\u003C\u002Fcolgroup\u003E\u003Cthead\u003E\u003Ctr\u003E\u003Cth\u003EProduct\u003C\u002Fth\u003E\u003Cth\u003EAffected\u003C\u002Fth\u003E";
if (st.show.unaffected) {
pug_html = pug_html + "\u003Cth\u003EUnaffected\u003C\u002Fth\u003E";
}
if (st.show.unknown) {
pug_html = pug_html + "\u003Cth\u003EUnknown\u003C\u002Fth\u003E";
}
pug_html = pug_html + "\u003C\u002Ftr\u003E\u003Ctbody\u003E";
// iterate st.groups
;(function(){
  var $$obj = st.groups;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var p = $$obj[i];
var showProd = st.vals[i].length
// iterate st.vals[i]
;(function(){
  var $$obj = st.vals[i];
  if ('number' == typeof $$obj.length) {
      for (var j = 0, $$l = $$obj.length; j < $$l; j++) {
        var x = $$obj[j];
pug_html = pug_html + "\u003Ctr\u003E";
if (showProd) {
pug_html = pug_html + "\u003Ctd" + (pug_attr("rowspan", showProd, true, false)) + "\u003E";
pug_mixins["prodDetails"](p);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
showProd = false
}
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.affected);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
if (st.show.unaffected) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.unaffected);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
if (st.show.unknown) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.unknown);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
pug_html = pug_html + "\u003C\u002Ftr\u003E";
      }
  } else {
    var $$l = 0;
    for (var j in $$obj) {
      $$l++;
      var x = $$obj[j];
pug_html = pug_html + "\u003Ctr\u003E";
if (showProd) {
pug_html = pug_html + "\u003Ctd" + (pug_attr("rowspan", showProd, true, false)) + "\u003E";
pug_mixins["prodDetails"](p);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
showProd = false
}
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.affected);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
if (st.show.unaffected) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.unaffected);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
if (st.show.unknown) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.unknown);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
pug_html = pug_html + "\u003C\u002Ftr\u003E";
    }
  }
}).call(this);

      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var p = $$obj[i];
var showProd = st.vals[i].length
// iterate st.vals[i]
;(function(){
  var $$obj = st.vals[i];
  if ('number' == typeof $$obj.length) {
      for (var j = 0, $$l = $$obj.length; j < $$l; j++) {
        var x = $$obj[j];
pug_html = pug_html + "\u003Ctr\u003E";
if (showProd) {
pug_html = pug_html + "\u003Ctd" + (pug_attr("rowspan", showProd, true, false)) + "\u003E";
pug_mixins["prodDetails"](p);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
showProd = false
}
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.affected);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
if (st.show.unaffected) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.unaffected);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
if (st.show.unknown) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.unknown);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
pug_html = pug_html + "\u003C\u002Ftr\u003E";
      }
  } else {
    var $$l = 0;
    for (var j in $$obj) {
      $$l++;
      var x = $$obj[j];
pug_html = pug_html + "\u003Ctr\u003E";
if (showProd) {
pug_html = pug_html + "\u003Ctd" + (pug_attr("rowspan", showProd, true, false)) + "\u003E";
pug_mixins["prodDetails"](p);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
showProd = false
}
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.affected);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
if (st.show.unaffected) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.unaffected);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
if (st.show.unknown) {
pug_html = pug_html + "\u003Ctd\u003E";
pug_mixins["versionList"](x.unknown);
pug_html = pug_html + "\u003C\u002Ftd\u003E";
}
pug_html = pug_html + "\u003C\u002Ftr\u003E";
    }
  }
}).call(this);

    }
  }
}).call(this);

pug_html = pug_html + "\u003C\u002Ftbody\u003E\u003C\u002Fthead\u003E\u003C\u002Ftable\u003E";
};
pug_mixins["creditList"] = pug_interp = function(credits){
var block = (this && this.block), attributes = (this && this.attributes) || {};
// iterate credits
;(function(){
  var $$obj = credits;
  if ('number' == typeof $$obj.length) {
      for (var pug_index11 = 0, $$l = $$obj.length; pug_index11 < $$l; pug_index11++) {
        var c = $$obj[pug_index11];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = c.value) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
      }
  } else {
    var $$l = 0;
    for (var pug_index11 in $$obj) {
      $$l++;
      var c = $$obj[pug_index11];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = c.value) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
    }
  }
}).call(this);

};
pug_mixins["tagList"] = pug_interp = function(tags){
var block = (this && this.block), attributes = (this && this.attributes) || {};
if (tags) {
// iterate tags
;(function(){
  var $$obj = tags;
  if ('number' == typeof $$obj.length) {
      for (var pug_index12 = 0, $$l = $$obj.length; pug_index12 < $$l; pug_index12++) {
        var t = $$obj[pug_index12];
pug_html = pug_html + "\u003Cb class=\"tag rnd CRITICAL\"\u003E" + (pug_escape(null == (pug_interp = t) ? "" : pug_interp)) + "\u003C\u002Fb\u003E  ";
      }
  } else {
    var $$l = 0;
    for (var pug_index12 in $$obj) {
      $$l++;
      var t = $$obj[pug_index12];
pug_html = pug_html + "\u003Cb class=\"tag rnd CRITICAL\"\u003E" + (pug_escape(null == (pug_interp = t) ? "" : pug_interp)) + "\u003C\u002Fb\u003E  ";
    }
  }
}).call(this);

}
};
pug_mixins["timeList"] = pug_interp = function(c){
var block = (this && this.block), attributes = (this && this.attributes) || {};
pug_html = pug_html + "\u003Cul\u003E";
// iterate c.timeline
;(function(){
  var $$obj = c.timeline;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var x = $$obj[i];
pug_html = pug_html + "\u003Cli\u003E";
pug_mixins["renderDate"](x.time);
pug_html = pug_html + " - " + (pug_escape(null == (pug_interp = x.value) ? "" : pug_interp)) + "\u003C\u002Fli\u003E";
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var x = $$obj[i];
pug_html = pug_html + "\u003Cli\u003E";
pug_mixins["renderDate"](x.time);
pug_html = pug_html + " - " + (pug_escape(null == (pug_interp = x.value) ? "" : pug_interp)) + "\u003C\u002Fli\u003E";
    }
  }
}).call(this);

pug_html = pug_html + "\u003C\u002Ful\u003E";
};
pug_mixins["refList"] = pug_interp = function(references){
var block = (this && this.block), attributes = (this && this.attributes) || {};
// iterate references
;(function(){
  var $$obj = references;
  if ('number' == typeof $$obj.length) {
      for (var pug_index14 = 0, $$l = $$obj.length; pug_index14 < $$l; pug_index14++) {
        var r = $$obj[pug_index14];
pug_html = pug_html + "\u003Cdiv\u003E";
var u = (new URL(r.url));
pug_html = pug_html + "\u003Cimg" + (" class=\"lbl\""+" width=\"16\" height=\"16\""+pug_attr("src", "https://www.google.com/s2/favicons?sz=32&domain_url="+u.protocol + '//'+ encodeURIComponent(u.hostname), true, false)) + "\u002F\u003E\u003Ca" + (pug_attr("href", r.url, true, false)) + "\u003E" + (pug_escape(null == (pug_interp = (r.name && r.name != "" && (r.name != r.url)) ?  u.hostname + " : " + r.name : u.hostname + u.pathname + u.search) ? "" : pug_interp)) + "\u003C\u002Fa\u003E";
if (r.tags && r.tags.length > 0) {
pug_html = pug_html + (" " + (pug_escape(null == (pug_interp = r.tags.map(x=>x.replace(/^x_refsource_/,"")).join(" ")) ? "" : pug_interp)));
}
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
      }
  } else {
    var $$l = 0;
    for (var pug_index14 in $$obj) {
      $$l++;
      var r = $$obj[pug_index14];
pug_html = pug_html + "\u003Cdiv\u003E";
var u = (new URL(r.url));
pug_html = pug_html + "\u003Cimg" + (" class=\"lbl\""+" width=\"16\" height=\"16\""+pug_attr("src", "https://www.google.com/s2/favicons?sz=32&domain_url="+u.protocol + '//'+ encodeURIComponent(u.hostname), true, false)) + "\u002F\u003E\u003Ca" + (pug_attr("href", r.url, true, false)) + "\u003E" + (pug_escape(null == (pug_interp = (r.name && r.name != "" && (r.name != r.url)) ?  u.hostname + " : " + r.name : u.hostname + u.pathname + u.search) ? "" : pug_interp)) + "\u003C\u002Fa\u003E";
if (r.tags && r.tags.length > 0) {
pug_html = pug_html + (" " + (pug_escape(null == (pug_interp = r.tags.map(x=>x.replace(/^x_refsource_/,"")).join(" ")) ? "" : pug_interp)));
}
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
    }
  }
}).call(this);

};
pug_mixins["errors"] = pug_interp = function(con){
var block = (this && this.block), attributes = (this && this.attributes) || {};
if (con.x_ValidationErrors) {
// iterate con.x_ValidationErrors
;(function(){
  var $$obj = con.x_ValidationErrors;
  if ('number' == typeof $$obj.length) {
      for (var pug_index15 = 0, $$l = $$obj.length; pug_index15 < $$l; pug_index15++) {
        var x = $$obj[pug_index15];
pug_html = pug_html + "\u003Cp class=\"sec rnd pad\"\u003E\u003Cb class=\"vgi-alert\"\u003EValidation Error : \u003C\u002Fb\u003E  \u003Cspan\u003E" + (pug_escape(null == (pug_interp = x) ? "" : pug_interp)) + "\u003C\u002Fspan\u003E\u003C\u002Fp\u003E";
      }
  } else {
    var $$l = 0;
    for (var pug_index15 in $$obj) {
      $$l++;
      var x = $$obj[pug_index15];
pug_html = pug_html + "\u003Cp class=\"sec rnd pad\"\u003E\u003Cb class=\"vgi-alert\"\u003EValidation Error : \u003C\u002Fb\u003E  \u003Cspan\u003E" + (pug_escape(null == (pug_interp = x) ? "" : pug_interp)) + "\u003C\u002Fspan\u003E\u003C\u002Fp\u003E";
    }
  }
}).call(this);

}
};
pug_mixins["warnings"] = pug_interp = function(con){
var block = (this && this.block), attributes = (this && this.attributes) || {};
if (con.x_ConverterErrors) {
// iterate con.x_ConverterErrors
;(function(){
  var $$obj = con.x_ConverterErrors;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var x = $$obj[i];
pug_html = pug_html + "\u003Cp class=\"sec rnd pad\"\u003E\u003Cb class=\"vgi-alert\"\u003EConversion Warning :  \u003C\u002Fb\u003E \u003Cb\u003E" + (pug_escape(null == (pug_interp = x.error) ? "" : pug_interp)) + "\u003C\u002Fb\u003E \u003Cspan\u003E" + (pug_escape(null == (pug_interp = x.message) ? "" : pug_interp)) + "\u003C\u002Fspan\u003E\u003C\u002Fp\u003E";
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var x = $$obj[i];
pug_html = pug_html + "\u003Cp class=\"sec rnd pad\"\u003E\u003Cb class=\"vgi-alert\"\u003EConversion Warning :  \u003C\u002Fb\u003E \u003Cb\u003E" + (pug_escape(null == (pug_interp = x.error) ? "" : pug_interp)) + "\u003C\u002Fb\u003E \u003Cspan\u003E" + (pug_escape(null == (pug_interp = x.message) ? "" : pug_interp)) + "\u003C\u002Fspan\u003E\u003C\u002Fp\u003E";
    }
  }
}).call(this);

}
};
pug_mixins["container"] = pug_interp = function(con){
var block = (this && this.block), attributes = (this && this.attributes) || {};
pug_html = pug_html + "\u003Cdiv class=\"cna pad\"\u003E";
if (cna[con.shortName] && cna[con.shortName].i) {
pug_html = pug_html + "\u003Cb\u003E\u003Cimg" + (" class=\"logo\""+pug_attr("src", "https://www.google.com/s2/favicons?sz=64&domain_url="+cna[con.shortName].i, true, false)) + "\u002F\u003E\u003C\u002Fb\u003E";
}
pug_html = pug_html + "\u003Cspan\u003E \u003Cb\u003E" + (pug_escape(null == (pug_interp = cna[con.shortName]? cna[con.shortName].n : con.shortName) ? "" : pug_interp)) + "\u003C\u002Fb\u003E\u003Cbr\u002F\u003E";
pug_mixins["renderDate"](con.datePublic);
if (con.dateUpdated && con.dateUpdated != con.datePublic) {
pug_html = pug_html + " (updated ";
pug_mixins["renderDate"](con.dateUpdated);
pug_html = pug_html + ")";
}
pug_html = pug_html + "\u003C\u002Fspan\u003E\u003Cspan class=\"right row\"\u003E";
pug_mixins["cvssList"](con.cvssList);
pug_html = pug_html + "\u003Cdetails class=\"popup\"\u003E\u003Csummary class=\"vgi-out sbn\"\u003E\u003C\u002Fsummary\u003E\u003Cdiv class=\"rnd pad pop wht bor shd\"\u003E\u003Ca" + (" class=\"sbn vgi-mail\""+" title=\"Share this CVE in email\""+pug_attr("href", "mailto:?subject="+con.cveId+ ' ' + con.TITLE+"&body="+con.cveId + (con.title ? ' ' + con.title:'')+"%0A%0Ahttps://vulnogram.github.io/seaview/?"+con.cveId, true, false)) + "\u003E\u003C\u002Fa\u003E\u003Cbr\u002F\u003E\u003Ca" + (" class=\"sbn vgi-tweet\""+" title=\"Share this CVE on Twitter\""+pug_attr("href", "https://twitter.com/intent/tweet?text="+con.cveId+ (con.title ? ' ' + con.title:'')+"&url=https://vulnogram.github.io/seaview/?"+con.cveId, true, false)+" target=\"_blank\"") + "\u003E\u003C\u002Fa\u003E\u003Cbr\u002F\u003E\u003Ca" + (" class=\"sbn vgi-link\""+pug_attr("href", "https://vulnogram.github.io/seaview/?"+con.cveId, true, false)+" target=\"_blank\"") + "\u003E\u003C\u002Fa\u003E\u003C\u002Fdiv\u003E\u003C\u002Fdetails\u003E\u003C\u002Fspan\u003E\u003C\u002Fdiv\u003E\u003Cdiv class=\"desc pad\"\u003E";
if (con.state == 'REJECTED') {
pug_html = pug_html + "\u003Cb class=\"tag CRITICAL\"\u003EREJECTED\u003C\u002Fb\u003E ·  ";
}
pug_mixins["tagList"](con.tags);
pug_html = pug_html + "\u003Cb\u003E" + (pug_escape(null == (pug_interp = con.cveId) ? "" : pug_interp)) + "\u003C\u002Fb\u003E ";
if (con.title) {
pug_html = pug_html + "\u003Cb\u003E" + (pug_escape(null == (pug_interp = con.title) ? "" : pug_interp)) + "\u003C\u002Fb\u003E";
}
pug_html = pug_html + " ";
pug_mixins["spara"](con.descriptions);
pug_mixins["spara"](con.rejectedReasons);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
if ((con.metrics && con.metrics.length > 0 && con.metrics[0].other && con.metrics[0].other.type == 'ssvc')) {
pug_html = pug_html + "\u003Cdiv class=\"metrics pad\"\u003E\u003Cb\u003EStakeholder Specific Vulnerability Catgorization (SSVC)\u003C\u002Fb\u003E";
// iterate con.metrics[0].other.content.options
;(function(){
  var $$obj = con.metrics[0].other.content.options;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var m = $$obj[i];
// iterate m
;(function(){
  var $$obj = m;
  if ('number' == typeof $$obj.length) {
      for (var j = 0, $$l = $$obj.length; j < $$l; j++) {
        var o = $$obj[j];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = j + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
      }
  } else {
    var $$l = 0;
    for (var j in $$obj) {
      $$l++;
      var o = $$obj[j];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = j + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
    }
  }
}).call(this);

      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var m = $$obj[i];
// iterate m
;(function(){
  var $$obj = m;
  if ('number' == typeof $$obj.length) {
      for (var j = 0, $$l = $$obj.length; j < $$l; j++) {
        var o = $$obj[j];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = j + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
      }
  } else {
    var $$l = 0;
    for (var j in $$obj) {
      $$l++;
      var o = $$obj[j];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = j + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
    }
  }
}).call(this);

    }
  }
}).call(this);

pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
if (con.configurations) {
pug_html = pug_html + "\u003Cdiv class=\"configs pad\"\u003E\u003Cb class=\"vgi-cog\"\u003ERequired configuration for exposure: \u003C\u002Fb\u003E";
pug_mixins["spara"](con.configurations);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
if (con.problemTypes) {
pug_html = pug_html + "\u003Cdiv class=\"problem pad\"\u003E\u003Cb class=\"vgi-bug\"\u003EProblem: \u003C\u002Fb\u003E ";
// iterate con.problemTypes
;(function(){
  var $$obj = con.problemTypes;
  if ('number' == typeof $$obj.length) {
      for (var pug_index20 = 0, $$l = $$obj.length; pug_index20 < $$l; pug_index20++) {
        var t = $$obj[pug_index20];
if (t.description) {
// iterate t.description
;(function(){
  var $$obj = t.description;
  if ('number' == typeof $$obj.length) {
      for (var pug_index21 = 0, $$l = $$obj.length; pug_index21 < $$l; pug_index21++) {
        var d = $$obj[pug_index21];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp)) + " ";
      }
  } else {
    var $$l = 0;
    for (var pug_index21 in $$obj) {
      $$l++;
      var d = $$obj[pug_index21];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp)) + " ";
    }
  }
}).call(this);

}
if (t.descriptions) {
// iterate t.descriptions
;(function(){
  var $$obj = t.descriptions;
  if ('number' == typeof $$obj.length) {
      for (var pug_index22 = 0, $$l = $$obj.length; pug_index22 < $$l; pug_index22++) {
        var d = $$obj[pug_index22];
pug_html = pug_html + "  ";
if (d.cweId) {
if (d.cweId != d.description) {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp)) + " ";
}
pug_html = pug_html + "\u003Ca" + (pug_attr("href", "https://cwe.mitre.org/data/definitions/"+d.cweId, true, false)) + "\u003E\u003Csmall\u003E" + (pug_escape(null == (pug_interp = d.cweId) ? "" : pug_interp)) + "\u003C\u002Fsmall\u003E\u003C\u002Fa\u003E ";
}
else {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp));
}
      }
  } else {
    var $$l = 0;
    for (var pug_index22 in $$obj) {
      $$l++;
      var d = $$obj[pug_index22];
pug_html = pug_html + "  ";
if (d.cweId) {
if (d.cweId != d.description) {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp)) + " ";
}
pug_html = pug_html + "\u003Ca" + (pug_attr("href", "https://cwe.mitre.org/data/definitions/"+d.cweId, true, false)) + "\u003E\u003Csmall\u003E" + (pug_escape(null == (pug_interp = d.cweId) ? "" : pug_interp)) + "\u003C\u002Fsmall\u003E\u003C\u002Fa\u003E ";
}
else {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp));
}
    }
  }
}).call(this);

}
      }
  } else {
    var $$l = 0;
    for (var pug_index20 in $$obj) {
      $$l++;
      var t = $$obj[pug_index20];
if (t.description) {
// iterate t.description
;(function(){
  var $$obj = t.description;
  if ('number' == typeof $$obj.length) {
      for (var pug_index23 = 0, $$l = $$obj.length; pug_index23 < $$l; pug_index23++) {
        var d = $$obj[pug_index23];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp)) + " ";
      }
  } else {
    var $$l = 0;
    for (var pug_index23 in $$obj) {
      $$l++;
      var d = $$obj[pug_index23];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp)) + " ";
    }
  }
}).call(this);

}
if (t.descriptions) {
// iterate t.descriptions
;(function(){
  var $$obj = t.descriptions;
  if ('number' == typeof $$obj.length) {
      for (var pug_index24 = 0, $$l = $$obj.length; pug_index24 < $$l; pug_index24++) {
        var d = $$obj[pug_index24];
pug_html = pug_html + "  ";
if (d.cweId) {
if (d.cweId != d.description) {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp)) + " ";
}
pug_html = pug_html + "\u003Ca" + (pug_attr("href", "https://cwe.mitre.org/data/definitions/"+d.cweId, true, false)) + "\u003E\u003Csmall\u003E" + (pug_escape(null == (pug_interp = d.cweId) ? "" : pug_interp)) + "\u003C\u002Fsmall\u003E\u003C\u002Fa\u003E ";
}
else {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp));
}
      }
  } else {
    var $$l = 0;
    for (var pug_index24 in $$obj) {
      $$l++;
      var d = $$obj[pug_index24];
pug_html = pug_html + "  ";
if (d.cweId) {
if (d.cweId != d.description) {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp)) + " ";
}
pug_html = pug_html + "\u003Ca" + (pug_attr("href", "https://cwe.mitre.org/data/definitions/"+d.cweId, true, false)) + "\u003E\u003Csmall\u003E" + (pug_escape(null == (pug_interp = d.cweId) ? "" : pug_interp)) + "\u003C\u002Fsmall\u003E\u003C\u002Fa\u003E ";
}
else {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp));
}
    }
  }
}).call(this);

}
    }
  }
}).call(this);

pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
if (con.impacts) {
pug_html = pug_html + "\u003Cdiv class=\"impact pad\"\u003E\u003Cb class=\"vgi-impact\"\u003EImpact:  \u003C\u002Fb\u003E Code-execution (link) \u003Ca href=\"https:\u002F\u002Fcapec.mitre.org\u002Fdata\u002Fdefinitions\u002F\"\u003E\u003Csmall\u003ECPAEC-123 \u003C\u002Fsmall\u003E\u003C\u002Fa\u003E\u003C\u002Fdiv\u003E";
}
if (con.exploits) {
pug_html = pug_html + "\u003Cdiv class=\"exploits pad\"\u003E\u003Cb class=\"vgi-bomb\"\u003EExploits\u003C\u002Fb\u003E";
pug_mixins["spara"](con.exploits);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
if (con.pvstatus) {
if (con.v4) {
pug_mixins["statusTablev4"](con.pvstatus);
}
else {
pug_mixins["statusTablev5"](con.pvstatus);
}
}
if (con.solutions) {
pug_html = pug_html + "\u003Cdiv class=\"solution pad\"\u003E\u003Cb class=\"vgi-safe\"\u003ESolution\u003C\u002Fb\u003E";
pug_mixins["spara"](con.solutions);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
if (con.workarounds) {
pug_html = pug_html + "\u003Cdiv class=\"workaround pad\"\u003E\u003Cb class=\"vgi-avoid\"\u003EWorkaround\u003C\u002Fb\u003E";
pug_mixins["spara"](con.workarounds);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
if (con.credits) {
pug_html = pug_html + "\u003Cdiv class=\"credits rnd pad sec\"\u003E\u003Cb class=\"vgi-like\"\u003ECredits\u003C\u002Fb\u003E";
pug_mixins["creditList"](con.credits);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
if (con.timeline) {
pug_html = pug_html + "\u003Cdiv class=\"timeline pad\"\u003E\u003Cdetails" + (pug_attr("open", true, true, false)) + "\u003E \u003Csummary\u003E\u003Cb class=\"vgi-cal\"\u003ETimeline\u003C\u002Fb\u003E\u003C\u002Fsummary\u003E";
pug_mixins["timeList"](con);
pug_html = pug_html + "\u003C\u002Fdetails\u003E\u003C\u002Fdiv\u003E";
}
if (con.references) {
pug_html = pug_html + "\u003Cdiv class=\"references pad\"\u003E\u003Cdetails" + (pug_attr("open", true, true, false)) + "\u003E \u003Csummary\u003E\u003Cb class=\"vgi-ext\"\u003EReferences\u003C\u002Fb\u003E\u003C\u002Fsummary\u003E";
pug_mixins["refList"](con.references);
pug_html = pug_html + "\u003C\u002Fdetails\u003E\u003C\u002Fdiv\u003E";
}
if (con.json) {
pug_html = pug_html + "\u003Cpre\u003E" + (pug_escape(null == (pug_interp = JSON.stringify(con.json,1,1)) ? "" : pug_interp)) + "\u003C\u002Fpre\u003E";
}
};
pug_mixins["para"] = pug_interp = function(t, hypertext, lang){
var block = (this && this.block), attributes = (this && this.attributes) || {};
if (t) {
if (hypertext) {
pug_html = pug_html + "\u003Cp" + (pug_attr("lang", lang, true, false)) + "\u003E" + (pug_escape(null == (pug_interp = t) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
}
else {
// iterate t.split(/\n/)
;(function(){
  var $$obj = t.split(/\n/);
  if ('number' == typeof $$obj.length) {
      for (var pug_index25 = 0, $$l = $$obj.length; pug_index25 < $$l; pug_index25++) {
        var line = $$obj[pug_index25];
if (line) {
if (line.startsWith('  ')) {
pug_html = pug_html + "\u003Ccode\u003E" + (pug_escape(null == (pug_interp = line) ? "" : pug_interp)) + "\u003C\u002Fcode\u003E\u003Cbr\u002F\u003E";
}
else {
pug_html = pug_html + "\u003Cp" + (pug_attr("lang", lang, true, false)) + "\u003E" + (pug_escape(null == (pug_interp = line) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
}
}
      }
  } else {
    var $$l = 0;
    for (var pug_index25 in $$obj) {
      $$l++;
      var line = $$obj[pug_index25];
if (line) {
if (line.startsWith('  ')) {
pug_html = pug_html + "\u003Ccode\u003E" + (pug_escape(null == (pug_interp = line) ? "" : pug_interp)) + "\u003C\u002Fcode\u003E\u003Cbr\u002F\u003E";
}
else {
pug_html = pug_html + "\u003Cp" + (pug_attr("lang", lang, true, false)) + "\u003E" + (pug_escape(null == (pug_interp = line) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
}
}
    }
  }
}).call(this);

}
}
};




































pug_mixins["spara"] = pug_interp = function(l, hypertext){
var block = (this && this.block), attributes = (this && this.attributes) || {};
if (l) {
// iterate l
;(function(){
  var $$obj = l;
  if ('number' == typeof $$obj.length) {
      for (var pug_index28 = 0, $$l = $$obj.length; pug_index28 < $$l; pug_index28++) {
        var d = $$obj[pug_index28];
if (d.supportingMedia && d.supportingMedia.length > 0 && d.supportingMedia[0].type == 'text/html') {
pug_html = pug_html + "\u003Cp" + (pug_attr("lang", d.lang, true, false)) + "\u003E" + (null == (pug_interp = d.supportingMedia[0].value) ? "" : pug_interp) + "\u003C\u002Fp\u003E";
}
else
if (d.value) {
pug_mixins["para"](d.value,null,d.lang);
}
      }
  } else {
    var $$l = 0;
    for (var pug_index28 in $$obj) {
      $$l++;
      var d = $$obj[pug_index28];
if (d.supportingMedia && d.supportingMedia.length > 0 && d.supportingMedia[0].type == 'text/html') {
pug_html = pug_html + "\u003Cp" + (pug_attr("lang", d.lang, true, false)) + "\u003E" + (null == (pug_interp = d.supportingMedia[0].value) ? "" : pug_interp) + "\u003C\u002Fp\u003E";
}
else
if (d.value) {
pug_mixins["para"](d.value,null,d.lang);
}
    }
  }
}).call(this);

}
};



























































pug_mixins["renderDate"] = pug_interp = function(value){
var block = (this && this.block), attributes = (this && this.attributes) || {};
var v = false;
if (value instanceof Date) { v = value;} else {
var timestamp = Date.parse(value);
v = isNaN(timestamp) ? false : new Date(timestamp)
}
if (v) {
pug_html = pug_html + (pug_escape(null == (pug_interp = v.toJSON().substr(0,10)) ? "" : pug_interp));
}
};
pug_mixins["JSON"] = pug_interp = function(d, par, comma){
var block = (this && this.block), attributes = (this && this.attributes) || {};
var k;
if (d instanceof Array) {
pug_html = pug_html + "\u003Cdetails" + (" class=\"arr\""+pug_attr("open", true, true, false)) + "\u003E\u003Csummary\u003E\u003Cb\u003E" + (pug_escape(null == (pug_interp = (par? par + ' : [' : '[')) ? "" : pug_interp)) + "\u003C\u002Fb\u003E\u003C\u002Fsummary\u003E\u003Cdiv class=\"in\"\u003E";
// iterate d
;(function(){
  var $$obj = d;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var s = $$obj[i];
pug_mixins["JSON"](s, undefined, i < d.length-1);
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var s = $$obj[i];
pug_mixins["JSON"](s, undefined, i < d.length-1);
    }
  }
}).call(this);

pug_html = pug_html + "\u003Cb\u003E]\u003C\u002Fb\u003E";
if (comma) {
pug_html = pug_html + "\u003Ci\u003E,\u003C\u002Fi\u003E";
}
pug_html = pug_html + "\u003C\u002Fdiv\u003E\u003C\u002Fdetails\u003E";
}
else
if (d instanceof Object) {
pug_html = pug_html + "\u003Cdetails" + (" class=\"obj\""+pug_attr("open", true, true, false)) + "\u003E\u003Csummary\u003E\u003Cb\u003E" + (pug_escape(null == (pug_interp = (par? par + ' : {' : '{')) ? "" : pug_interp)) + "\u003C\u002Fb\u003E\u003C\u002Fsummary\u003E\u003Cdiv class=\"in\"\u003E";
var keys = Object.keys(d)
// iterate keys
;(function(){
  var $$obj = keys;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var k = $$obj[i];
if (d.hasOwnProperty(k)) {
pug_mixins["JSON"](d[k], k, i < keys.length-1);
}
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var k = $$obj[i];
if (d.hasOwnProperty(k)) {
pug_mixins["JSON"](d[k], k, i < keys.length-1);
}
    }
  }
}).call(this);

pug_html = pug_html + "\u003Cb\u003E}\u003C\u002Fb\u003E";
if (comma) {
pug_html = pug_html + "\u003Ci\u003E,\u003C\u002Fi\u003E";
}
pug_html = pug_html + "\u003C\u002Fdiv\u003E\u003C\u002Fdetails\u003E";
}
else {
if (par) {
pug_html = pug_html + "\u003Cdiv" + (pug_attr("class", pug_classes(["i",(typeof d === 'number' ? 'n' : '')], [false,true]), false, false)) + "\u003E\u003Cb\u003E" + (pug_escape(null == (pug_interp = par + ' : ') ? "" : pug_interp)) + "\u003C\u002Fb\u003E";
pug_mixins["showVal"](d, comma);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
else {
pug_html = pug_html + "\u003Cdiv" + (pug_attr("class", pug_classes([(typeof d === 'number' ? 'n' : '')], [true]), false, false)) + "\u003E";
pug_mixins["showVal"](d, comma);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
}
};
pug_mixins["showVal"] = pug_interp = function(d, comma){
var block = (this && this.block), attributes = (this && this.attributes) || {};
if (typeof d === 'string') {
pug_html = pug_html + "\u003Ci\u003E\"\u003C\u002Fi\u003E" + (pug_escape(null == (pug_interp = d) ? "" : pug_interp)) + "\u003Ci\u003E\"\u003C\u002Fi\u003E";
}
else {
pug_html = pug_html + (pug_escape(null == (pug_interp = d) ? "" : pug_interp));
}
if (comma) {
pug_html = pug_html + "\u003Ci\u003E,\u003C\u002Fi\u003E";
}
};
pug_mixins["versionList"] = pug_interp = function(v){
var block = (this && this.block), attributes = (this && this.attributes) || {};
if (v) {
var n = v.shift();
while (n != undefined) {
pug_html = pug_html + (pug_escape(null == (pug_interp = n) ? "" : pug_interp));
if (v.length > 0) {
pug_html = pug_html + "\u003Chr\u002F\u003E";
}
n = v.shift();
}
}
};
pug_mixins["cve5"] = pug_interp = function(cve){
var block = (this && this.block), attributes = (this && this.attributes) || {};
pug_html = pug_html + "\u003Cdiv class=\"pad\"\u003E";
var CDM = cve.cveMetadata;
var con = cve.containers ? cve.containers.cna : {};
//var jsonClone = {};
//Object.assign(jsonClone, cve.containers.cna);
//delete con.json;
//con.json = jsonClone;
//delete con.json.x_legacyV4Record;
//con.x_ValidationErrors = cve.x_ValidationErrors;
con.state = CDM.state;
con.cveId = CDM.cveId;
var PMD = cve.containers.cna.providerMetadata;
con.dateUpdated = PMD.dateUpdated;
con.shortName = PMD.shortName;
var title = con.title;
var sourceText = {"INTERNAL":"This issue was found during internal product security testing or research.", "EXTERNAL":"This issue was discovered during an external security research.", "USER":"This issue was seen during production usage.", "UNKNOWN":""};
var cveId = CDM.cveId.match("^CVE-[0-9-]+$") ? CDM.cveId : 'CVE-yyyy-nnnn';
con.cvssList = [];
con.pvstatus = con.affected ? statusFunction(con.affected) : null;
if ((con.metrics && con.metrics.length > 0)) {
// iterate con.metrics
;(function(){
  var $$obj = con.metrics;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var x = $$obj[i];
var cvss = x.cvssV4_0 ? x.cvssV4_0 : x.cvssV3_1 ? x.cvssV3_1 : x.cvssV3_0 ? x.cvssV3_0 : x.cvssV2_0 ? x.cvssV2_0 : null;
if (cvss) {
cvss.scenarios = x.scenarios;
con.cvssList.push(cvss);
}
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var x = $$obj[i];
var cvss = x.cvssV4_0 ? x.cvssV4_0 : x.cvssV3_1 ? x.cvssV3_1 : x.cvssV3_0 ? x.cvssV3_0 : x.cvssV2_0 ? x.cvssV2_0 : null;
if (cvss) {
cvss.scenarios = x.scenarios;
con.cvssList.push(cvss);
}
    }
  }
}).call(this);

}
pug_mixins["container"](con);
if ((cve.containers.adp && cve.containers.adp.length > 0)) {
// iterate cve.containers.adp
;(function(){
  var $$obj = cve.containers.adp;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var x = $$obj[i];
var PMD = x.providerMetadata;
x.dateUpdated = PMD.dateUpdated;
x.shortName = PMD.shortName;
pug_mixins["container"](x);
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var x = $$obj[i];
var PMD = x.providerMetadata;
x.dateUpdated = PMD.dateUpdated;
x.shortName = PMD.shortName;
pug_mixins["container"](x);
    }
  }
}).call(this);

}
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
};
pug_mixins["cve4"] = pug_interp = function(cve){
var block = (this && this.block), attributes = (this && this.attributes) || {};
pug_html = pug_html + "\u003Cdiv class=\"pad\"\u003E";
var sourceText = {"INTERNAL":"internally", "EXTERNAL":"externally", "USER":"in production use", "UNKNOWN":""};
var sourceTitle = {"INTERNAL":"This issue was found during internal security review or testing.", "EXTERNAL":"This issue was found during external security research or testing.", "USER":"A customer encountered this issue while using the product.", "UNKNOWN":""};
var con = {v4:true};
Object.assign(con, cve);
var CDM = cve ? cve.CVE_data_meta : null;
if (CDM) {
    con.shortName = CDM.ASSIGNER;
    con.cveId = CDM.ID;
    con.title = CDM.TITLE;
    con.datePublic = CDM.DATE_PUBLIC
    con.dateUpdated = CDM.DATE_UPDATED
}
//con.json = cve;
if (con.impact && con.impact.cvss) {
    con.cvssList = [con.impact.cvss]
}
con.descriptions = con.description ? con.description.description_data : null;
con.configurations = con.configuration ? con.configuration : null;
con.exploits = con.exploit ? con.exploit : null;
con.pvstatus = con.affects ? statusFunction(con.affects) : null;
con.solutions = con.solution ? con.solution : null;
con.workarounds = con.work_around ? con.work_around : null;
con.credits = con.credit ? con.credit : null;
con.problemTypes = con.problemtype ? con.problemtype.problemtype_data : null;
con.references = con.references? con.references.reference_data : null;
pug_mixins["container"](con);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
};













































if (renderTemplate == 'cve4') {
pug_mixins["cve4"](d);
}
else
if (renderTemplate == 'cve5') {
pug_mixins["cve5"](d);
}
else
if (renderTemplate == 'JSON') {
pug_mixins["JSON"](d);
}
else
if (renderTemplate == 'warnings') {
pug_mixins["warnings"](d.containers.cna);
}
else
if (renderTemplate == 'errors') {
pug_mixins["errors"](d.containers.cna);
}
    }.call(this, "Array" in locals_for_with ?
        locals_for_with.Array :
        typeof Array !== 'undefined' ? Array : undefined, "Date" in locals_for_with ?
        locals_for_with.Date :
        typeof Date !== 'undefined' ? Date : undefined, "JSON" in locals_for_with ?
        locals_for_with.JSON :
        typeof JSON !== 'undefined' ? JSON : undefined, "Object" in locals_for_with ?
        locals_for_with.Object :
        typeof Object !== 'undefined' ? Object : undefined, "URL" in locals_for_with ?
        locals_for_with.URL :
        typeof URL !== 'undefined' ? URL : undefined, "cna" in locals_for_with ?
        locals_for_with.cna :
        typeof cna !== 'undefined' ? cna : undefined, "d" in locals_for_with ?
        locals_for_with.d :
        typeof d !== 'undefined' ? d : undefined, "encodeURIComponent" in locals_for_with ?
        locals_for_with.encodeURIComponent :
        typeof encodeURIComponent !== 'undefined' ? encodeURIComponent : undefined, "isNaN" in locals_for_with ?
        locals_for_with.isNaN :
        typeof isNaN !== 'undefined' ? isNaN : undefined, "nonSpec" in locals_for_with ?
        locals_for_with.nonSpec :
        typeof nonSpec !== 'undefined' ? nonSpec : undefined, "renderTemplate" in locals_for_with ?
        locals_for_with.renderTemplate :
        typeof renderTemplate !== 'undefined' ? renderTemplate : undefined, "statusFunction" in locals_for_with ?
        locals_for_with.statusFunction :
        typeof statusFunction !== 'undefined' ? statusFunction : undefined));
    ;;return pug_html;}