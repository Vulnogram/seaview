function pug_attr(t,e,n,r){if(!1===e||null==e||!e&&("class"===t||"style"===t))return"";if(!0===e)return" "+(r?t:t+'="'+t+'"');var f=typeof e;return"object"!==f&&"function"!==f||"function"!=typeof e.toJSON||(e=e.toJSON()),"string"==typeof e||(e=JSON.stringify(e),n||-1===e.indexOf('"'))?(n&&(e=pug_escape(e))," "+t+'="'+e+'"'):" "+t+"='"+e.replace(/'/g,"&#39;")+"'"}
function pug_classes(s,r){return Array.isArray(s)?pug_classes_array(s,r):s&&"object"==typeof s?pug_classes_object(s):s||""}
function pug_classes_array(r,a){for(var s,e="",u="",c=Array.isArray(a),g=0;g<r.length;g++)(s=pug_classes(r[g]))&&(c&&a[g]&&(s=pug_escape(s)),e=e+u+s,u=" ");return e}
function pug_classes_object(r){var a="",n="";for(var o in r)o&&r[o]&&pug_has_own_property.call(r,o)&&(a=a+n+o,n=" ");return a}
function pug_escape(e){var a=""+e,t=pug_match_html.exec(a);if(!t)return e;var r,c,n,s="";for(r=t.index,c=0;r<a.length;r++){switch(a.charCodeAt(r)){case 34:n="&quot;";break;case 38:n="&amp;";break;case 60:n="&lt;";break;case 62:n="&gt;";break;default:continue}c!==r&&(s+=a.substring(c,r)),c=r+1,s+=n}return c!==r?s+a.substring(c,r):s}
var pug_has_own_property=Object.prototype.hasOwnProperty;
var pug_match_html=/["&<>]/;
function pug_style(r){if(!r)return"";if("object"==typeof r){var t="";for(var e in r)pug_has_own_property.call(r,e)&&(t=t+e+":"+r[e]+";");return t}return r+""}function cve(locals) {var pug_html = "", pug_mixins = {}, pug_interp;;
    var locals_for_with = (locals || {});
    
    (function (Array, Date, JSON, Object, URL, cna, con, cvssDesc, cvssSeverity, d, encodeURIComponent, formatFriendlyDate, getGradientColor, icon, isNaN, nonSpec, num, renderTemplate, shownURLs, statusFunctionv4, structuredClone) {
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
pug_html = pug_html + "\u003Cdetails class=\"popup\"\u003E";
var score = cvss.threatScore || cvss.baseScore;
var sev = cvss.threatSeverity || cvss.baseSeverity || cvssSeverity(score);
pug_html = pug_html + "\u003Csummary" + (" class=\"lbl rnd tag\""+pug_attr("style", pug_style(score ? ("background-color:"+getGradientColor(score)+';'+(score >= 8 ? 'color:#fff;':'color:#000;')):false), true, false)+pug_attr("title", score + ' out of 10', true, false)) + "\u003E" + (pug_escape(null == (pug_interp = sev) ? "" : pug_interp)) + " · \u003Cb\u003E" + (pug_escape(null == (pug_interp = score) ? "" : pug_interp)) + "\u003C\u002Fb\u003E\u003C\u002Fsummary\u003E\u003Cdiv class=\"pop wht rnd shd pad bor\"\u003E";
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
pug_html = pug_html + "\u003Ca" + (" class=\"vgi-ext\""+pug_attr("href", "https://vulnogram.org/cvss4?" + cvss.vectorString, true, false)) + "\u003EOpen CVSS Calc\u003C\u002Fa\u003E";
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
pug_html = pug_html + "\u003Cdetails class=\"popup\"\u003E";
var score = cvss.threatScore || cvss.baseScore;
var sev = cvss.threatSeverity || cvss.baseSeverity || cvssSeverity(score);
pug_html = pug_html + "\u003Csummary" + (" class=\"lbl rnd tag\""+pug_attr("style", pug_style(score ? ("background-color:"+getGradientColor(score)+';'+(score >= 8 ? 'color:#fff;':'color:#000;')):false), true, false)+pug_attr("title", score + ' out of 10', true, false)) + "\u003E" + (pug_escape(null == (pug_interp = sev) ? "" : pug_interp)) + " · \u003Cb\u003E" + (pug_escape(null == (pug_interp = score) ? "" : pug_interp)) + "\u003C\u002Fb\u003E\u003C\u002Fsummary\u003E\u003Cdiv class=\"pop wht rnd shd pad bor\"\u003E";
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
pug_html = pug_html + "\u003Ca" + (" class=\"vgi-ext\""+pug_attr("href", "https://vulnogram.org/cvss4?" + cvss.vectorString, true, false)) + "\u003EOpen CVSS Calc\u003C\u002Fa\u003E";
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
pug_html = pug_html + "\u003Cb" + (pug_attr("class", pug_classes(["tag","rnd",icon[t]], [false,false,true]), false, false)) + "\u003E" + (pug_escape(null == (pug_interp = t) ? "" : pug_interp)) + "\u003C\u002Fb\u003E  ";
      }
  } else {
    var $$l = 0;
    for (var pug_index12 in $$obj) {
      $$l++;
      var t = $$obj[pug_index12];
pug_html = pug_html + "\u003Cb" + (pug_attr("class", pug_classes(["tag","rnd",icon[t]], [false,false,true]), false, false)) + "\u003E" + (pug_escape(null == (pug_interp = t) ? "" : pug_interp)) + "\u003C\u002Fb\u003E  ";
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
if ((shownURLs && !shownURLs[r.url])) {
var u = (new URL(r.url));
shownURLs[r.url] = true;
pug_html = pug_html + "\u003Cimg" + (" class=\"lbl\""+" width=\"16\" height=\"16\""+pug_attr("src", "https://www.google.com/s2/favicons?sz=32&domain_url="+u.protocol + '//'+ encodeURIComponent(u.hostname), true, false)) + "\u002F\u003E\u003Ca" + (pug_attr("href", r.url, true, false)) + "\u003E" + (pug_escape(null == (pug_interp = (r.name && r.name != "" && (r.name != r.url)) ?  u.hostname + " : " + r.name : u.hostname + u.pathname + u.search) ? "" : pug_interp)) + "\u003C\u002Fa\u003E";
if (r.tags && r.tags.length > 0) {
pug_html = pug_html + (" " + (pug_escape(null == (pug_interp = r.tags.map(x=>x.replace(/^x_refsource_/,"")).join(" ")) ? "" : pug_interp)));
}
}
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
      }
  } else {
    var $$l = 0;
    for (var pug_index14 in $$obj) {
      $$l++;
      var r = $$obj[pug_index14];
pug_html = pug_html + "\u003Cdiv\u003E";
if ((shownURLs && !shownURLs[r.url])) {
var u = (new URL(r.url));
shownURLs[r.url] = true;
pug_html = pug_html + "\u003Cimg" + (" class=\"lbl\""+" width=\"16\" height=\"16\""+pug_attr("src", "https://www.google.com/s2/favicons?sz=32&domain_url="+u.protocol + '//'+ encodeURIComponent(u.hostname), true, false)) + "\u002F\u003E\u003Ca" + (pug_attr("href", r.url, true, false)) + "\u003E" + (pug_escape(null == (pug_interp = (r.name && r.name != "" && (r.name != r.url)) ?  u.hostname + " : " + r.name : u.hostname + u.pathname + u.search) ? "" : pug_interp)) + "\u003C\u002Fa\u003E";
if (r.tags && r.tags.length > 0) {
pug_html = pug_html + (" " + (pug_escape(null == (pug_interp = r.tags.map(x=>x.replace(/^x_refsource_/,"")).join(" ")) ? "" : pug_interp)));
}
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
pug_mixins["container"] = pug_interp = function(con, cve){
var block = (this && this.block), attributes = (this && this.attributes) || {};
pug_html = pug_html + "\u003Cdiv class=\"cna pad\"\u003E";
var cList = con.providerMetadata? con.providerMetadata.orgId : (cve? cve.cveMetadata.assignerOrgId : false)
var cUrl = cna[con.shortName] && cna[con.shortName].i ? cna[con.shortName].i : false
if (cUrl) {
pug_html = pug_html + "\u003Ca" + (pug_attr("href", '?CNA:'+cList, true, false)) + "\u003E\u003Cimg" + (" class=\"logo\""+pug_attr("src", "https://www.google.com/s2/favicons?sz=128&domain_url="+cna[con.shortName].i, true, false)) + "\u002F\u003E\u003C\u002Fa\u003E";
}
pug_html = pug_html + "\u003Cspan\u003E \u003Ca" + (" class=\"bld\""+pug_attr("href", '?CNA:'+cList, true, false)) + "\u003E" + (pug_escape(null == (pug_interp = cna[con.shortName]? cna[con.shortName].n : con.shortName) ? "" : pug_interp)) + "\u003C\u002Fa\u003E";
if (cUrl) {
pug_html = pug_html + "\u003Ca" + (" class=\"vgi-globe\""+pug_attr("href", cUrl, true, false)) + "\u003E\u003C\u002Fa\u003E";
}
pug_html = pug_html + "\u003Cbr\u002F\u003E";
var publicDate = con.datePublic || (cve ? cve.cveMetadata.datePublished : false);
var publishDate = (cve ? cve.cveMetadata.datePublished : false) || con.datePublic;
pug_mixins["renderDate"](publicDate);
if ((con.dateUpdated || publishDate) && con.dateUpdated != publishDate) {
pug_html = pug_html + " (updated ";
pug_mixins["renderDate"](con.dateUpdated);
pug_html = pug_html + ")";
}
pug_html = pug_html + "\u003C\u002Fspan\u003E\u003Cspan class=\"flx\"\u003E ";
pug_mixins["cvssList"](con.cvssList);
if (con.KEV) {
pug_html = pug_html + "\u003Csummary class=\"lbl rnd tag CVSS CRITICAL vgi-bomb\"\u003EKnown Exploited Since " + (pug_escape(null == (pug_interp = con.KEV.dateAdded) ? "" : pug_interp)) + "\u003C\u002Fsummary\u003E";
}
pug_html = pug_html + "\u003Ca" + (" class=\"sbn vgi-mail\""+" title=\"Share this CVE in email\""+pug_attr("href", "mailto:?subject="+con.cveId+ ' ' + (con.title?con.title:'')+"&body="+con.cveId + (con.title ? ' ' + con.title:'')+"%0A%0Ahttps://vulnogram.org/seaview/?"+con.cveId, true, false)) + "\u003E\u003C\u002Fa\u003E\u003Ca" + (" class=\"sbn vgi-link\""+pug_attr("href", "https://vulnogram.org/seaview/?"+con.cveId, true, false)+" target=\"_blank\"") + "\u003E\u003C\u002Fa\u003E";
if (con.jsonURL) {
pug_html = pug_html + "\u003Ca" + (" class=\"sbn vgi-versions\""+pug_attr("href", con.jsonURL, true, false)+" target=\"_blank\" title=\"View in GitHub\"") + "\u003E\u003C\u002Fa\u003E";
}
pug_html = pug_html + "\u003C\u002Fspan\u003E\u003C\u002Fdiv\u003E\u003Cdiv class=\"desc pad\"\u003E";
if (con.state == 'REJECTED') {
con.maxCVSS = -1;
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
if ((con.metrics && con.metrics.length > 0)) {
// iterate con.metrics
;(function(){
  var $$obj = con.metrics;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var metric = $$obj[i];
if ((con.metrics[i].other && con.metrics[i].other.type == 'ssvc')) {
pug_html = pug_html + "\u003Cdiv class=\"metrics pad\"\u003E\u003Cb\u003EStakeholder Specific Vulnerability Catgorization (SSVC)\u003C\u002Fb\u003E";
// iterate con.metrics[i].other.content.options
;(function(){
  var $$obj = con.metrics[i].other.content.options;
  if ('number' == typeof $$obj.length) {
      for (var j = 0, $$l = $$obj.length; j < $$l; j++) {
        var m = $$obj[j];
// iterate m
;(function(){
  var $$obj = m;
  if ('number' == typeof $$obj.length) {
      for (var k = 0, $$l = $$obj.length; k < $$l; k++) {
        var o = $$obj[k];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = k + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
      }
  } else {
    var $$l = 0;
    for (var k in $$obj) {
      $$l++;
      var o = $$obj[k];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = k + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
    }
  }
}).call(this);

      }
  } else {
    var $$l = 0;
    for (var j in $$obj) {
      $$l++;
      var m = $$obj[j];
// iterate m
;(function(){
  var $$obj = m;
  if ('number' == typeof $$obj.length) {
      for (var k = 0, $$l = $$obj.length; k < $$l; k++) {
        var o = $$obj[k];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = k + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
      }
  } else {
    var $$l = 0;
    for (var k in $$obj) {
      $$l++;
      var o = $$obj[k];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = k + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
    }
  }
}).call(this);

    }
  }
}).call(this);

pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var metric = $$obj[i];
if ((con.metrics[i].other && con.metrics[i].other.type == 'ssvc')) {
pug_html = pug_html + "\u003Cdiv class=\"metrics pad\"\u003E\u003Cb\u003EStakeholder Specific Vulnerability Catgorization (SSVC)\u003C\u002Fb\u003E";
// iterate con.metrics[i].other.content.options
;(function(){
  var $$obj = con.metrics[i].other.content.options;
  if ('number' == typeof $$obj.length) {
      for (var j = 0, $$l = $$obj.length; j < $$l; j++) {
        var m = $$obj[j];
// iterate m
;(function(){
  var $$obj = m;
  if ('number' == typeof $$obj.length) {
      for (var k = 0, $$l = $$obj.length; k < $$l; k++) {
        var o = $$obj[k];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = k + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
      }
  } else {
    var $$l = 0;
    for (var k in $$obj) {
      $$l++;
      var o = $$obj[k];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = k + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
    }
  }
}).call(this);

      }
  } else {
    var $$l = 0;
    for (var j in $$obj) {
      $$l++;
      var m = $$obj[j];
// iterate m
;(function(){
  var $$obj = m;
  if ('number' == typeof $$obj.length) {
      for (var k = 0, $$l = $$obj.length; k < $$l; k++) {
        var o = $$obj[k];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = k + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
      }
  } else {
    var $$l = 0;
    for (var k in $$obj) {
      $$l++;
      var o = $$obj[k];
pug_html = pug_html + "\u003Cp\u003E" + (pug_escape(null == (pug_interp = k + ': ' + o) ? "" : pug_interp)) + "\u003C\u002Fp\u003E";
    }
  }
}).call(this);

    }
  }
}).call(this);

pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
    }
  }
}).call(this);

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
      for (var pug_index24 = 0, $$l = $$obj.length; pug_index24 < $$l; pug_index24++) {
        var t = $$obj[pug_index24];
if (t.description) {
// iterate t.description
;(function(){
  var $$obj = t.description;
  if ('number' == typeof $$obj.length) {
      for (var pug_index25 = 0, $$l = $$obj.length; pug_index25 < $$l; pug_index25++) {
        var d = $$obj[pug_index25];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp)) + " ";
      }
  } else {
    var $$l = 0;
    for (var pug_index25 in $$obj) {
      $$l++;
      var d = $$obj[pug_index25];
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
      for (var pug_index26 = 0, $$l = $$obj.length; pug_index26 < $$l; pug_index26++) {
        var d = $$obj[pug_index26];
pug_html = pug_html + "  ";
if (d.cweId) {
if (d.cweId != d.description) {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp));
}
if (num = d.cweId.match(/\d+/)[0]) {
pug_html = pug_html + " \u003Ca" + (pug_attr("href", "https://cwe.mitre.org/data/definitions/"+num, true, false)) + "\u003E\u003Csmall\u003E" + (pug_escape(null == (pug_interp = d.cweId) ? "" : pug_interp)) + "\u003C\u002Fsmall\u003E\u003C\u002Fa\u003E ";
}
}
else {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp));
}
      }
  } else {
    var $$l = 0;
    for (var pug_index26 in $$obj) {
      $$l++;
      var d = $$obj[pug_index26];
pug_html = pug_html + "  ";
if (d.cweId) {
if (d.cweId != d.description) {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp));
}
if (num = d.cweId.match(/\d+/)[0]) {
pug_html = pug_html + " \u003Ca" + (pug_attr("href", "https://cwe.mitre.org/data/definitions/"+num, true, false)) + "\u003E\u003Csmall\u003E" + (pug_escape(null == (pug_interp = d.cweId) ? "" : pug_interp)) + "\u003C\u002Fsmall\u003E\u003C\u002Fa\u003E ";
}
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
    for (var pug_index24 in $$obj) {
      $$l++;
      var t = $$obj[pug_index24];
if (t.description) {
// iterate t.description
;(function(){
  var $$obj = t.description;
  if ('number' == typeof $$obj.length) {
      for (var pug_index27 = 0, $$l = $$obj.length; pug_index27 < $$l; pug_index27++) {
        var d = $$obj[pug_index27];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp)) + " ";
      }
  } else {
    var $$l = 0;
    for (var pug_index27 in $$obj) {
      $$l++;
      var d = $$obj[pug_index27];
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
      for (var pug_index28 = 0, $$l = $$obj.length; pug_index28 < $$l; pug_index28++) {
        var d = $$obj[pug_index28];
pug_html = pug_html + "  ";
if (d.cweId) {
if (d.cweId != d.description) {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp));
}
if (num = d.cweId.match(/\d+/)[0]) {
pug_html = pug_html + " \u003Ca" + (pug_attr("href", "https://cwe.mitre.org/data/definitions/"+num, true, false)) + "\u003E\u003Csmall\u003E" + (pug_escape(null == (pug_interp = d.cweId) ? "" : pug_interp)) + "\u003C\u002Fsmall\u003E\u003C\u002Fa\u003E ";
}
}
else {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp));
}
      }
  } else {
    var $$l = 0;
    for (var pug_index28 in $$obj) {
      $$l++;
      var d = $$obj[pug_index28];
pug_html = pug_html + "  ";
if (d.cweId) {
if (d.cweId != d.description) {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.description) ? "" : pug_interp));
}
if (num = d.cweId.match(/\d+/)[0]) {
pug_html = pug_html + " \u003Ca" + (pug_attr("href", "https://cwe.mitre.org/data/definitions/"+num, true, false)) + "\u003E\u003Csmall\u003E" + (pug_escape(null == (pug_interp = d.cweId) ? "" : pug_interp)) + "\u003C\u002Fsmall\u003E\u003C\u002Fa\u003E ";
}
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
pug_html = pug_html + "\u003Cdiv class=\"impact pad\"\u003E\u003Cb class=\"vgi-impact\"\u003EImpact:  \u003C\u002Fb\u003E ";
// iterate con.impacts
;(function(){
  var $$obj = con.impacts;
  if ('number' == typeof $$obj.length) {
      for (var pug_index29 = 0, $$l = $$obj.length; pug_index29 < $$l; pug_index29++) {
        var t = $$obj[pug_index29];
if (t.description) {
// iterate t.description
;(function(){
  var $$obj = t.description;
  if ('number' == typeof $$obj.length) {
      for (var pug_index30 = 0, $$l = $$obj.length; pug_index30 < $$l; pug_index30++) {
        var d = $$obj[pug_index30];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp)) + " ";
      }
  } else {
    var $$l = 0;
    for (var pug_index30 in $$obj) {
      $$l++;
      var d = $$obj[pug_index30];
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
      for (var pug_index31 = 0, $$l = $$obj.length; pug_index31 < $$l; pug_index31++) {
        var d = $$obj[pug_index31];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp));
      }
  } else {
    var $$l = 0;
    for (var pug_index31 in $$obj) {
      $$l++;
      var d = $$obj[pug_index31];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp));
    }
  }
}).call(this);

}
if (t.capecId) {
if (num = t.capecId.match(/\d+/)[0]) {
pug_html = pug_html + " \u003Ca" + (pug_attr("href", "https://capec.mitre.org/data/definitions/"+num, true, false)) + "\u003E\u003Csmall\u003E" + (pug_escape(null == (pug_interp = t.capecId) ? "" : pug_interp)) + "\u003C\u002Fsmall\u003E\u003C\u002Fa\u003E ";
}
}
      }
  } else {
    var $$l = 0;
    for (var pug_index29 in $$obj) {
      $$l++;
      var t = $$obj[pug_index29];
if (t.description) {
// iterate t.description
;(function(){
  var $$obj = t.description;
  if ('number' == typeof $$obj.length) {
      for (var pug_index32 = 0, $$l = $$obj.length; pug_index32 < $$l; pug_index32++) {
        var d = $$obj[pug_index32];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp)) + " ";
      }
  } else {
    var $$l = 0;
    for (var pug_index32 in $$obj) {
      $$l++;
      var d = $$obj[pug_index32];
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
      for (var pug_index33 = 0, $$l = $$obj.length; pug_index33 < $$l; pug_index33++) {
        var d = $$obj[pug_index33];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp));
      }
  } else {
    var $$l = 0;
    for (var pug_index33 in $$obj) {
      $$l++;
      var d = $$obj[pug_index33];
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp));
    }
  }
}).call(this);

}
if (t.capecId) {
if (num = t.capecId.match(/\d+/)[0]) {
pug_html = pug_html + " \u003Ca" + (pug_attr("href", "https://capec.mitre.org/data/definitions/"+num, true, false)) + "\u003E\u003Csmall\u003E" + (pug_escape(null == (pug_interp = t.capecId) ? "" : pug_interp)) + "\u003C\u002Fsmall\u003E\u003C\u002Fa\u003E ";
}
}
    }
  }
}).call(this);

pug_html = pug_html + "\u003C\u002Fdiv\u003E";
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
pug_mixins["refList"](con.references, con);
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
      for (var pug_index34 = 0, $$l = $$obj.length; pug_index34 < $$l; pug_index34++) {
        var line = $$obj[pug_index34];
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
    for (var pug_index34 in $$obj) {
      $$l++;
      var line = $$obj[pug_index34];
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
pug_mixins["text"] = pug_interp = function(l){
var block = (this && this.block), attributes = (this && this.attributes) || {};
if (l) {
// iterate l
;(function(){
  var $$obj = l;
  if ('number' == typeof $$obj.length) {
      for (var pug_index35 = 0, $$l = $$obj.length; pug_index35 < $$l; pug_index35++) {
        var d = $$obj[pug_index35];
if (d.value) {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp));
}
      }
  } else {
    var $$l = 0;
    for (var pug_index35 in $$obj) {
      $$l++;
      var d = $$obj[pug_index35];
if (d.value) {
pug_html = pug_html + (pug_escape(null == (pug_interp = d.value) ? "" : pug_interp));
}
    }
  }
}).call(this);

}
};
pug_mixins["spara"] = pug_interp = function(l, hypertext){
var block = (this && this.block), attributes = (this && this.attributes) || {};
if (l) {
// iterate l
;(function(){
  var $$obj = l;
  if ('number' == typeof $$obj.length) {
      for (var pug_index36 = 0, $$l = $$obj.length; pug_index36 < $$l; pug_index36++) {
        var d = $$obj[pug_index36];
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
    for (var pug_index36 in $$obj) {
      $$l++;
      var d = $$obj[pug_index36];
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
pug_html = pug_html + "\u003Cspan" + (pug_attr("title", v.toString(), true, false)) + "\u003E" + (pug_escape(null == (pug_interp = formatFriendlyDate(v)) ? "" : pug_interp)) + "\u003C\u002Fspan\u003E";
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
var keys = Object.keys(d)
pug_html = pug_html + "\u003Cdetails" + (" class=\"obj\""+pug_attr("open", (keys.lenth<6?true:false), true, false)) + "\u003E\u003Csummary\u003E\u003Cb\u003E" + (pug_escape(null == (pug_interp = (par? par + ' : {' : '{')) ? "" : pug_interp)) + "\u003C\u002Fb\u003E\u003C\u002Fsummary\u003E\u003Cdiv class=\"in\"\u003E";
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
var con = cve.containers.cna;
var adpContainers = (cve.containers && cve.containers.adp ? cve.containers.adp : []);
shownURLs = {};
con.jsonURL = cve.jsonURL;
pug_html = pug_html + "\u003Cdiv class=\"pad\"\u003E";
pug_mixins["container"](con,cve);
if (adpContainers && adpContainers.length > 0) {
// iterate adpContainers
;(function(){
  var $$obj = adpContainers;
  if ('number' == typeof $$obj.length) {
      for (var i = 0, $$l = $$obj.length; i < $$l; i++) {
        var x = $$obj[i];
pug_html = pug_html + "\u003Chr class=\"line\"\u002F\u003E";
pug_mixins["container"](x);
      }
  } else {
    var $$l = 0;
    for (var i in $$obj) {
      $$l++;
      var x = $$obj[i];
pug_html = pug_html + "\u003Chr class=\"line\"\u002F\u003E";
pug_mixins["container"](x);
    }
  }
}).call(this);

}
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
};
pug_mixins["row"] = pug_interp = function(cve){
var block = (this && this.block), attributes = (this && this.attributes) || {};
con = cve.containers.cna;
pug_html = pug_html + "\u003Ca" + (" class=\"flx nowrap\""+pug_attr("href", "#"+con.cveId, true, false)+pug_attr("data-id", con.cveId, true, false)+pug_attr("data-score", (con.state == 'REJECTED'?-1:con.maxCVSS||0), true, false)+pug_attr("data-date", con.date, true, false)) + "\u003E";
if (cna[con.shortName] && cna[con.shortName].i) {
pug_html = pug_html + "\u003Cimg" + (pug_attr("title", con.shortName, true, false)+" width=\"28\" height=\"28\""+pug_attr("src", "https://www.google.com/s2/favicons?sz=64&domain_url="+cna[con.shortName].i, true, false)) + "\u002F\u003E";
}
else {
pug_html = pug_html + "\u003Cimg" + (pug_attr("title", con.shortName, true, false)+" width=\"28\" height=\"28\" src=\"https:\u002F\u002Fvulnogram.org\u002Fvg-icons\u002Fsrc\u002Fbug.svg\"") + "\u002F\u003E";
}
pug_html = pug_html + ("\u003Cb" + (pug_attr("class", pug_classes([(con.state == 'REJECTED'?'rej':'')], [true]), false, false)+pug_attr("style", pug_style(con.maxCVSS ? ("background-color:"+getGradientColor(con.maxCVSS)+';'+(con.maxCVSS >= 8 ? 'color:#fff;':'color:#000;')):false), true, false)) + "\u003E" + (pug_escape(null == (pug_interp = con.cveId) ? "" : pug_interp)));
if (con.maxCVSS) {
pug_html = pug_html + (" · " + (pug_escape(null == (pug_interp = con.maxCVSS) ? "" : pug_interp)));
}
pug_html = pug_html + "\u003C\u002Fb\u003E";
if ((con.tags && con.tags.includes('disputed'))) {
pug_html = pug_html + "\u003Ci class=\"vgi-what\" title=\"Disputed\"\u003E\u003C\u002Fi\u003E";
}
if ((cve.KEV)) {
pug_html = pug_html + "\u003Ci class=\"vgi-bomb\" title=\"Known exploited!\"\u003E\u003C\u002Fi\u003E";
}
if ((con.tags && con.tags.includes('exclusively-hosted-service'))) {
pug_html = pug_html + "\u003Ci class=\"vgi-cloud\" title=\"Cloud vulnerability\"\u003E\u003C\u002Fi\u003E";
}
if ((con.tags && con.tags.includes('unsupported-when-assigned'))) {
pug_html = pug_html + "\u003Ci class=\"vgi-no\" title=\"Unsupported product\"\u003E\u003C\u002Fi\u003E";
}
pug_html = pug_html + "\u003Cspan\u003E";
if (con.title) {
pug_html = pug_html + (pug_escape(null == (pug_interp = con.title) ? "" : pug_interp));
}
else {
pug_mixins["text"](con.descriptions);
pug_mixins["text"](con.rejectedReasons);
}
pug_html = pug_html + "\u003C\u002Fspan\u003E\u003Cb class=\"dt\"\u003E" + (pug_escape(null == (pug_interp = formatFriendlyDate(con.date)) ? "" : pug_interp)) + "\u003C\u002Fb\u003E\u003C\u002Fa\u003E";
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
con.pvstatus = con.affects ? statusFunctionv4(con.affects) : null;
con.solutions = con.solution ? con.solution : null;
con.workarounds = con.work_around ? con.work_around : null;
con.credits = con.credit ? con.credit : null;
con.problemTypes = con.problemtype ? con.problemtype.problemtype_data : null;
con.references = con.references? con.references.reference_data : null;
pug_mixins["container"](con);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
};
pug_mixins["entry"] = pug_interp = function(d){
var block = (this && this.block), attributes = (this && this.attributes) || {};
var con = d.containers ? d.containers.cna : {};
var cve4doc = con.x_legacyV4Record;
delete con.x_legacyV4Record;

pug_html = pug_html + "\u003Cdiv" + (" class=\"wht\""+pug_attr("id", d.cveMetadata.cveId, true, false)) + "\u003E";
pug_mixins["cve5"](d,{cvssDesc: cvssDesc});
pug_html = pug_html + "\u003Cdiv class=\"pad fade borTop\"\u003E\u003Cb\u003ECVE-JSON Record\u003Ca" + (" class=\"vgi-versions\""+pug_attr("href", d.jsonURL, true, false)+" target=\"_blank\" title=\"View in GitHub\"") + "\u003E\u003C\u002Fa\u003E\u003C\u002Fb\u003E\u003Cdiv class=\"jsonBox\"\u003E";
pug_mixins["JSON"](d.oldJSON);
pug_html = pug_html + "\u003C\u002Fdiv\u003E\u003C\u002Fdiv\u003E";
if (con.x_ValidationErrors) {
pug_html = pug_html + "\u003Cdiv class=\"bor rnd wht shd page\"\u003E";
pug_mixins["errors"].call({
block: function(){
pug_html = pug_html + "  ";
}
}, con);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
if (cve4doc) {
pug_html = pug_html + "\u003Cdetails class=\"pad fade borTop\"\u003E\u003Csummary\u003E\u003Cb\u003ELegacy CVE-JSON 4 Record \u003C\u002Fb\u003E\u003C\u002Fsummary\u003E\u003Cdiv\u003E";
var oDoc = structuredClone(cve4doc)
pug_mixins["cve4"](cve4doc);
pug_html = pug_html + "\u003Cdiv class=\"pad\"\u003E\u003Cb\u003ECVE-JSON Record\u003Ca" + (" class=\"sbn vgi-versions\""+pug_attr("href", d.jsonURL, true, false)+" target=\"_blank\" title=\"View in GitHub\"") + "\u003E\u003C\u002Fa\u003E\u003C\u002Fb\u003E\u003Cdiv class=\"jsonBox\"\u003E";
pug_mixins["JSON"](oDoc);
pug_html = pug_html + "\u003C\u002Fdiv\u003E\u003C\u002Fdiv\u003E";
if (con.x_ConverterErrors) {
pug_html = pug_html + "\u003Cdiv class=\"bor rnd wht shd page\"\u003E";
pug_mixins["warnings"](con);
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
}
pug_html = pug_html + "\u003C\u002Fdiv\u003E\u003C\u002Fdetails\u003E";
}
pug_html = pug_html + "\u003C\u002Fdiv\u003E";
};
if (renderTemplate == 'row') {
pug_mixins["row"](d);
}
else
if (renderTemplate == 'entry') {
pug_mixins["entry"](d);
}
else
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
        typeof cna !== 'undefined' ? cna : undefined, "con" in locals_for_with ?
        locals_for_with.con :
        typeof con !== 'undefined' ? con : undefined, "cvssDesc" in locals_for_with ?
        locals_for_with.cvssDesc :
        typeof cvssDesc !== 'undefined' ? cvssDesc : undefined, "cvssSeverity" in locals_for_with ?
        locals_for_with.cvssSeverity :
        typeof cvssSeverity !== 'undefined' ? cvssSeverity : undefined, "d" in locals_for_with ?
        locals_for_with.d :
        typeof d !== 'undefined' ? d : undefined, "encodeURIComponent" in locals_for_with ?
        locals_for_with.encodeURIComponent :
        typeof encodeURIComponent !== 'undefined' ? encodeURIComponent : undefined, "formatFriendlyDate" in locals_for_with ?
        locals_for_with.formatFriendlyDate :
        typeof formatFriendlyDate !== 'undefined' ? formatFriendlyDate : undefined, "getGradientColor" in locals_for_with ?
        locals_for_with.getGradientColor :
        typeof getGradientColor !== 'undefined' ? getGradientColor : undefined, "icon" in locals_for_with ?
        locals_for_with.icon :
        typeof icon !== 'undefined' ? icon : undefined, "isNaN" in locals_for_with ?
        locals_for_with.isNaN :
        typeof isNaN !== 'undefined' ? isNaN : undefined, "nonSpec" in locals_for_with ?
        locals_for_with.nonSpec :
        typeof nonSpec !== 'undefined' ? nonSpec : undefined, "num" in locals_for_with ?
        locals_for_with.num :
        typeof num !== 'undefined' ? num : undefined, "renderTemplate" in locals_for_with ?
        locals_for_with.renderTemplate :
        typeof renderTemplate !== 'undefined' ? renderTemplate : undefined, "shownURLs" in locals_for_with ?
        locals_for_with.shownURLs :
        typeof shownURLs !== 'undefined' ? shownURLs : undefined, "statusFunctionv4" in locals_for_with ?
        locals_for_with.statusFunctionv4 :
        typeof statusFunctionv4 !== 'undefined' ? statusFunctionv4 : undefined, "structuredClone" in locals_for_with ?
        locals_for_with.structuredClone :
        typeof structuredClone !== 'undefined' ? structuredClone : undefined));
    ;;return pug_html;}