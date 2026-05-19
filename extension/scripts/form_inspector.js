// Form Action Domain Mismatch Detection for VigilantLink
// Content script — inspects form structure for phishing signals
// Never reads or transmits field values — attribute/structure inspection only
// Runs at document_idle, monitors DOM mutations with debounce

(function() {
  'use strict';

  // ── Configuration ──────────────────────────────────────────────────────────
  var DEBOUNCE_MS = 400;
  var MAX_FORMS_TO_INSPECT = 50; // Safety cap for performance
  var _debounceTimer = null;
  var _lastResultHash = ''; // Avoid sending duplicate results

  // ── Suspicious hidden field names ──────────────────────────────────────────
  var SUSPICIOUS_HIDDEN_NAMES = [
    'user', 'username', 'login', 'email', 'mail', 'e-mail',
    'pass', 'password', 'passwd', 'pwd', 'credential',
    'token', 'auth', 'auth_token', 'session', 'sessionid',
    'ssn', 'social', 'credit_card', 'cc_number', 'cvv', 'cardnumber',
    'pin', 'otp', 'secret', 'apikey', 'api_key'
  ];

  // ── Utility: Extract registered domain from hostname ───────────────────────
  function getRegisteredDomain(hostname) {
    if (!hostname) return '';
    var parts = hostname.toLowerCase().split('.');
    if (parts.length <= 2) return parts.join('.');

    // Handle two-part TLDs
    var twoPartTLDs = [
      'co.uk','com.br','co.in','com.au','co.jp','co.kr','com.mx',
      'org.uk','net.au','com.sg','com.hk','co.nz','co.za','com.ar',
      'com.tw','co.th','com.cn','com.tr','com.ua','co.id'
    ];
    var lastTwo = parts.slice(-2).join('.');
    if (twoPartTLDs.indexOf(lastTwo) !== -1 && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  // ── Utility: Resolve form action URL ───────────────────────────────────────
  function resolveFormAction(form) {
    var action = form.getAttribute('action');
    if (!action || action.trim() === '' || action.trim() === '#') {
      return null; // No meaningful action — JS-intercepted
    }

    try {
      // Resolve relative URLs against the form's base URI
      return new URL(action, form.baseURI || window.location.href);
    } catch (e) {
      return null;
    }
  }

  // ── Utility: Check if a form has credential fields ─────────────────────────
  function hasCredentialFields(form) {
    var passwordFields = form.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) return true;

    var emailFields = form.querySelectorAll(
      'input[type="email"], input[name*="email"], input[name*="mail"], ' +
      'input[autocomplete="email"], input[autocomplete="username"]'
    );
    if (emailFields.length > 0) return true;

    // Check for login-like input names
    var allInputs = form.querySelectorAll('input[type="text"], input:not([type])');
    for (var i = 0; i < allInputs.length; i++) {
      var name = (allInputs[i].name || '').toLowerCase();
      var autocomplete = (allInputs[i].autocomplete || '').toLowerCase();
      if (name.indexOf('user') !== -1 || name.indexOf('login') !== -1 ||
          autocomplete === 'username' || autocomplete === 'current-password') {
        return true;
      }
    }

    return false;
  }

  // ── Utility: Check for suspicious hidden fields ────────────────────────────
  function findSuspiciousHiddenFields(form) {
    var hiddens = form.querySelectorAll('input[type="hidden"]');
    var suspicious = [];

    for (var i = 0; i < hiddens.length; i++) {
      var name = (hiddens[i].name || '').toLowerCase();
      var id = (hiddens[i].id || '').toLowerCase();
      var hasValue = hiddens[i].value && hiddens[i].value.length > 0;

      for (var j = 0; j < SUSPICIOUS_HIDDEN_NAMES.length; j++) {
        var keyword = SUSPICIOUS_HIDDEN_NAMES[j];
        if ((name.indexOf(keyword) !== -1 || id.indexOf(keyword) !== -1) && hasValue) {
          suspicious.push(name || id);
          break;
        }
      }
    }

    return suspicious;
  }

  // ── Core: Inspect all forms on the page ────────────────────────────────────
  function inspectForms() {
    var result = {
      score: 0,
      flags: [],
      explanations: []
    };

    var pageDomain = getRegisteredDomain(window.location.hostname);
    var pageProtocol = window.location.protocol;
    var forms;

    try {
      forms = document.querySelectorAll('form');
    } catch (e) {
      return result;
    }

    if (!forms || forms.length === 0) return result;

    var formsToCheck = Math.min(forms.length, MAX_FORMS_TO_INSPECT);
    var actionDomains = new Set();
    var mismatchCount = 0;

    for (var i = 0; i < formsToCheck; i++) {
      var form = forms[i];
      var actionUrl = resolveFormAction(form);
      var hasCreds = hasCredentialFields(form);
      var hasPassword = form.querySelectorAll('input[type="password"]').length > 0;

      // ── Signal 1: Action-less form with password field ───────────────────
      if (!actionUrl && hasPassword) {
        result.score += 15;
        result.flags.push('ACTIONLESS_PASSWORD_FORM');
        result.explanations.push(
          'Password form has no action attribute — submission intercepted by JavaScript'
        );
        continue; // No action to compare domains against
      }

      if (!actionUrl) continue;

      var actionDomain = getRegisteredDomain(actionUrl.hostname);
      actionDomains.add(actionDomain);

      // ── Signal 2: Action domain mismatch ────────────────────────────────
      if (actionDomain && actionDomain !== pageDomain) {
        mismatchCount++;

        if (hasCreds) {
          // ── Signal 4: Credential fields + third-party action ────────────
          result.score += 25;
          result.flags.push('CRED_FORM_MISMATCH');
          result.explanations.push(
            'Credential form submits to external domain (' + actionDomain +
            ') instead of current site (' + pageDomain + ')'
          );
        } else {
          result.score += 10;
          result.flags.push('FORM_ACTION_MISMATCH');
          result.explanations.push(
            'Form submits data to a different domain (' + actionDomain + ')'
          );
        }

        // ── Signal 3: HTTP page with cross-origin HTTPS action ──────────
        if (pageProtocol === 'http:' && actionUrl.protocol === 'https:') {
          result.score += 8;
          result.flags.push('HTTP_CRED_HARVEST');
          result.explanations.push(
            'Insecure page sends form data to HTTPS endpoint — possible credential interception'
          );
        }
      }

      // ── Signal 5: Suspicious hidden fields ──────────────────────────────
      var suspiciousHidden = findSuspiciousHiddenFields(form);
      if (suspiciousHidden.length >= 2) {
        result.score += 12;
        result.flags.push('HIDDEN_CRED_FIELDS');
        result.explanations.push(
          'Form contains hidden credential-like fields (' +
          suspiciousHidden.slice(0, 3).join(', ') + ')'
        );
      } else if (suspiciousHidden.length === 1 && (hasCreds || mismatchCount > 0)) {
        result.score += 6;
        result.flags.push('HIDDEN_CRED_FIELDS');
      }
    }

    // ── Signal 6: Multiple forms with conflicting action domains ──────────
    if (actionDomains.size >= 3) {
      result.score += 15;
      result.flags.push('MULTI_DOMAIN_FORMS');
      result.explanations.push(
        'Page contains forms submitting to ' + actionDomains.size +
        ' different domains — possible injection or link farming'
      );
    }

    // Clamp score
    result.score = Math.min(55, Math.max(0, result.score));

    return result;
  }

  // ── Inspect and send results ───────────────────────────────────────────────
  function runInspectionAndReport() {
    var result = inspectForms();

    // Also try to inspect accessible iframes
    try {
      var iframes = document.querySelectorAll('iframe');
      for (var i = 0; i < Math.min(iframes.length, 10); i++) {
        try {
          var iframeDoc = iframes[i].contentDocument;
          if (iframeDoc) {
            var iframeForms = iframeDoc.querySelectorAll('form');
            if (iframeForms.length > 0) {
              // Re-run inspection logic on iframe forms
              var iframeDomain = getRegisteredDomain(iframes[i].src ?
                new URL(iframes[i].src).hostname : window.location.hostname);
              var pageDomain = getRegisteredDomain(window.location.hostname);

              if (iframeDomain !== pageDomain) {
                for (var f = 0; f < Math.min(iframeForms.length, 5); f++) {
                  if (hasCredentialFields(iframeForms[f])) {
                    result.score += 20;
                    result.flags.push('IFRAME_CRED_FORM');
                    result.explanations.push(
                      'Cross-origin iframe (' + iframeDomain +
                      ') contains credential form'
                    );
                    break; // One flag per iframe is sufficient
                  }
                }
              }
            }
          }
        } catch (e) {
          // SecurityError on cross-origin iframe — expected, skip silently
        }
      }
    } catch (e) {
      // Iframe access failed entirely — continue
    }

    // Re-clamp after iframe analysis
    result.score = Math.min(60, Math.max(0, result.score));

    // Deduplicate: only send if result changed
    var hash = result.score + ':' + result.flags.join(',');
    if (hash === _lastResultHash) return;
    _lastResultHash = hash;

    // Only send if there are actual findings
    if (result.score > 0) {
      try {
        chrome.runtime.sendMessage({
          type: 'FORM_RISK',
          payload: result
        });
      } catch (e) {
        // Extension context may be invalid — fail silently
      }
    }
  }

  // ── Debounced inspection trigger ───────────────────────────────────────────
  function scheduleInspection() {
    if (_debounceTimer) clearTimeout(_debounceTimer);
    _debounceTimer = setTimeout(function() {
      _debounceTimer = null;
      runInspectionAndReport();
    }, DEBOUNCE_MS);
  }

  // ── MutationObserver: Detect dynamically injected forms ────────────────────
  function startObserver() {
    var observer = new MutationObserver(function(mutations) {
      var hasRelevantChange = false;
      for (var i = 0; i < mutations.length; i++) {
        var mutation = mutations[i];
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          for (var j = 0; j < mutation.addedNodes.length; j++) {
            var node = mutation.addedNodes[j];
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (node.tagName === 'FORM' || (node.querySelector && node.querySelector('form'))) {
                hasRelevantChange = true;
                break;
              }
              // Also detect input fields added outside forms (overlay phishing)
              if (node.tagName === 'INPUT' && node.type === 'password') {
                hasRelevantChange = true;
                break;
              }
            }
          }
        }
        if (hasRelevantChange) break;
      }
      if (hasRelevantChange) {
        scheduleInspection();
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  // ── Initialize ─────────────────────────────────────────────────────────────
  // Run initial inspection after a short delay to let the page settle
  setTimeout(function() {
    runInspectionAndReport();
    startObserver();
  }, 500);

})();
