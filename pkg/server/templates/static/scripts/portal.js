// portal.js — shared utilities for all admin portal pages
// Requires AUTH_PREFIX, CSRF_TOKEN, and PORTAL_USER to be defined before this script.

function fmtTime(t) {
  if (!t || t.startsWith('0001-')) return '—';
  return new Date(t).toLocaleString();
}

function initials(name) {
  return (name || '?').slice(0, 2).toUpperCase();
}

function jsonHeaders() {
  return { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN };
}

function apiError(resp, fallback) {
  return resp.json().then(function(d) {
    return d.error || d.message || fallback;
  }).catch(function() { return fallback; });
}

// portalUser returns shared reactive state for the top-right profile popover.
// Call this once in each page's setup() and spread into the return object.
function useProfile() {
  const showProfile = Vue.ref(false);
  function toggleProfile(e) { e && e.stopPropagation(); showProfile.value = !showProfile.value; }
  function closeProfile() { showProfile.value = false; }
  Vue.onMounted(function() { document.addEventListener('click', closeProfile); });
  Vue.onUnmounted(function() { document.removeEventListener('click', closeProfile); });
  return { showProfile, toggleProfile, closeProfile };
}

// ISO 3166-1 alpha-2 country list resolved via Intl.DisplayNames.
var countryOptions = (function() {
  var iso2 = [
    'AD','AE','AF','AG','AL','AM','AO','AR','AT','AU','AZ','BA','BB','BD','BE','BF','BG','BH','BI','BJ',
    'BN','BO','BR','BS','BT','BW','BY','BZ','CA','CD','CF','CG','CH','CI','CL','CM','CN','CO','CR','CU',
    'CV','CY','CZ','DE','DJ','DK','DM','DO','DZ','EC','EE','EG','ER','ES','ET','FI','FJ','FM','FR','GA',
    'GB','GD','GE','GH','GM','GN','GQ','GR','GT','GW','GY','HN','HR','HT','HU','ID','IE','IL','IN','IQ',
    'IR','IS','IT','JM','JO','JP','KE','KG','KH','KI','KM','KN','KP','KR','KW','KZ','LA','LB','LC','LI',
    'LK','LR','LS','LT','LU','LV','LY','MA','MC','MD','ME','MG','MH','MK','ML','MM','MN','MR','MT','MU',
    'MV','MW','MX','MY','MZ','NA','NE','NG','NI','NL','NO','NP','NR','NZ','OM','PA','PE','PG','PH','PK',
    'PL','PT','PW','PY','QA','RO','RS','RU','RW','SA','SB','SC','SD','SE','SG','SI','SK','SL','SM','SN',
    'SO','SR','SS','ST','SV','SY','SZ','TD','TG','TH','TJ','TL','TM','TN','TO','TR','TT','TV','TZ','UA',
    'UG','US','UY','UZ','VA','VC','VE','VN','VU','WS','YE','ZA','ZM','ZW',
  ];
  var names = new Intl.DisplayNames(['en'], { type: 'region' });
  return iso2
    .map(function(c) { return { code: c, label: names.of(c) || c }; })
    .sort(function(a, b) { return a.label.localeCompare(b.label); });
})();
