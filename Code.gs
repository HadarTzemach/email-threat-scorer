function getApiKey() {
  return PropertiesService.getScriptProperties().getProperty("VT_API_KEY");
}

// Run this function ONCE manually to store your API key securely
function setApiKey() {
  PropertiesService.getScriptProperties()
    .setProperty("VT_API_KEY", "YOUR_API_KEY_HERE");
}

// --- Main Trigger Function ---

function onGmailMessage(e) {
  var messageId = e.gmail.messageId;
  var message = GmailApp.getMessageById(messageId);
  
  var from = message.getFrom();
  var subject = message.getSubject();
  var body = message.getPlainBody();
  var replyTo = message.getHeader("Reply-To");
  
  // Extract URLs once for reuse
  var urlRegex = /https?:\/\/[^\s<>"{}|\\^\[\]`]+/g;
  var extractedUrls = body.match(urlRegex) || [];
  
  var signals = [];
  var score = 0;
  
  // Check 1: Sender analysis
  var senderResult = analyzeSender(from, replyTo);
  score += senderResult.score;
  signals = signals.concat(senderResult.signals);
  
  // Check 2: Content analysis
  var contentResult = analyzeContent(subject, body);
  score += contentResult.score;
  signals = signals.concat(contentResult.signals);
  
  // Check 3: Link analysis
  var linkResult = analyzeLinks(extractedUrls);
  score += linkResult.score;
  signals = signals.concat(linkResult.signals);
  
  // Check 4: VirusTotal URL enrichment
  var vtResult = checkVirusTotal(extractedUrls);
  score += vtResult.score;
  signals = signals.concat(vtResult.signals);
  
  // Check 5: Blacklist check
  var blacklistResult = checkBlacklist(from);
  score += blacklistResult.score;
  signals = signals.concat(blacklistResult.signals);
  
  // Check 6: Attachment analysis
  var attachmentResult = analyzeAttachments(message);
  score += attachmentResult.score;
  signals = signals.concat(attachmentResult.signals);
  
  // Cap score at 100
  score = Math.min(score, 100);
  
  // Determine verdict
  var verdict = getVerdict(score);
  
  // Build the UI card
  return buildResultCard(score, verdict, signals, from, subject);
}

// --- Helper: Extract email and domain ---

function extractEmailParts(fromField) {
  var emailMatch = fromField.match(/<(.+?)>/);
  var email = emailMatch ? emailMatch[1] : fromField;
  email = email.toLowerCase().trim();
  var parts = email.split("@");
  var domain = parts.length > 1 ? parts[1] : email;
  return { email: email, domain: domain };
}

// --- Analysis Functions ---

function analyzeSender(from, replyTo) {
  var score = 0;
  var signals = [];
  
  var sender = extractEmailParts(from);
  
  // Check: Reply-To different from sender
  if (replyTo) {
    var replyToParts = extractEmailParts(replyTo);
    if (sender.email !== replyToParts.email) {
      score += 25;
      signals.push("⚠️ Reply-To (" + replyToParts.email + ") differs from sender (" + sender.email + ")");
    }
  }
  
  // Check: Free email provider
  var freeProviders = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", 
                       "aol.com", "mail.com", "protonmail.com"];
  if (freeProviders.includes(sender.domain)) {
    score += 5;
    signals.push("ℹ️ Sent from free email provider: " + sender.domain);
  }
  
  // Check: Unusually long domain
  if (sender.domain.length > 30) {
    score += 15;
    signals.push("⚠️ Unusually long sender domain: " + sender.domain);
  }
  
  // Check: Many numbers in domain
  var numberCount = (sender.domain.match(/\d/g) || []).length;
  if (numberCount > 4) {
    score += 10;
    signals.push("⚠️ Sender domain contains many numbers: " + sender.domain);
  }
  
  return { score: score, signals: signals };
}

function analyzeContent(subject, body) {
  var score = 0;
  var signals = [];
  
  var text = (subject + " " + body).toLowerCase();
  
  // Urgency phrases commonly used in phishing
  var urgencyPhrases = [
    "act now", "immediate action", "urgent", "account suspended",
    "verify your account", "confirm your identity", "unauthorized access",
    "click here immediately", "limited time", "your account will be closed",
    "security alert", "suspicious activity", "update your payment",
    "you have been selected", "congratulations you won"
  ];
  
  var urgencyCount = 0;
  urgencyPhrases.forEach(function(phrase) {
    var regex = new RegExp("\\b" + phrase + "\\b", "i");
    if (regex.test(text)) {
      urgencyCount++;
    }
  });
  
  if (urgencyCount > 0) {
    score += Math.min(urgencyCount * 8, 30);
    signals.push("🚨 Urgency/phishing phrases found (" + urgencyCount + " matches)");
  }
  
  // Check: Asks for sensitive information
  var sensitivePatterns = [
    "password", "credit card", "social security", "ssn", "bank account",
    "login credentials", "pin number", "routing number"
  ];
  
  var sensitiveCount = 0;
  sensitivePatterns.forEach(function(pattern) {
    var regex = new RegExp("\\b" + pattern + "\\b", "i");
    if (regex.test(text)) {
      sensitiveCount++;
    }
  });
  
  if (sensitiveCount > 0) {
    score += 20;
    signals.push("🚨 Email requests sensitive information (" + sensitiveCount + " patterns matched)");
  }
  
  // Check: Excessive CAPS in subject
  var capsWords = subject.split(" ").filter(function(word) {
    return word.length > 2 && word === word.toUpperCase() && /[A-Z]/.test(word);
  });
  
  if (capsWords.length >= 3) {
    score += 10;
    signals.push("⚠️ Subject contains excessive CAPS: " + capsWords.join(", "));
  }
  
  // Check: Empty subject
  if (!subject || subject.trim() === "") {
    score += 10;
    signals.push("⚠️ Email has no subject line");
  }
  
  return { score: score, signals: signals };
}

function analyzeLinks(urls) {
  var score = 0;
  var signals = [];
  
  if (urls.length === 0) {
    return { score: score, signals: signals };
  }
  
  // Check: Too many links
  if (urls.length > 10) {
    score += 10;
    signals.push("⚠️ Email contains many links (" + urls.length + ")");
  }
  
  var shortenedDomains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", 
                          "ow.ly", "is.gd", "buff.ly", "short.io"];
  var spoofTargets = ["paypal.com", "google.com", "microsoft.com", "apple.com",
                      "amazon.com", "facebook.com", "netflix.com", "bank"];
  
  var suspiciousCount = 0;
  var shortenedCount = 0;
  var ipCount = 0;
  var spoofCount = 0;
  
  urls.forEach(function(url) {
    var urlLower = url.toLowerCase();
    
    var domainMatch = urlLower.match(/https?:\/\/([^\/\:]+)/);
    var domain = domainMatch ? domainMatch[1] : "";
    
    // Check: IP address instead of domain
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlLower)) {
      ipCount++;
    }
    
    // Check: Shortened URL
    shortenedDomains.forEach(function(shortDomain) {
      if (domain.includes(shortDomain)) {
        shortenedCount++;
      }
    });
    
    // Check: Subdomain spoofing
    spoofTargets.forEach(function(target) {
      if (domain.includes(target) && !domain.endsWith(target)) {
        spoofCount++;
      }
    });
    
    // Check: Suspicious keywords in URL
    var suspiciousUrlPatterns = ["login", "verify", "secure", "account", 
                                 "update", "confirm", "banking"];
    suspiciousUrlPatterns.forEach(function(pattern) {
      if (urlLower.includes(pattern)) {
        suspiciousCount++;
      }
    });
  });
  
  if (ipCount > 0) {
    score += 25;
    signals.push("🚨 " + ipCount + " link(s) use IP address instead of domain");
  }
  
  if (shortenedCount > 0) {
    score += 15;
    signals.push("⚠️ " + shortenedCount + " shortened link(s) found");
  }
  
  if (spoofCount > 0) {
    score += 30;
    signals.push("🚨 " + spoofCount + " link(s) impersonate known brands (subdomain spoofing)");
  }
  
  if (suspiciousCount > 0) {
    score += Math.min(suspiciousCount * 5, 20);
    signals.push("⚠️ Links contain suspicious keywords (" + suspiciousCount + " matches)");
  }
  
  return { score: score, signals: signals };
}

function analyzeAttachments(message) {
  var score = 0;
  var signals = [];
  
  var attachments = message.getAttachments();
  
  if (attachments.length === 0) {
    return { score: score, signals: signals };
  }
  
  var dangerousExtensions = ["exe", "bat", "cmd", "vbs", "js", "wsf", "scr",
                              "pif", "msi", "jar", "ps1", "reg", "lnk", "hta"];
  var suspiciousExtensions = ["zip", "rar", "7z", "iso", "img", "docm", "xlsm", "pptm"];
  
  var dangerousCount = 0;
  var suspiciousCount = 0;
  var doubleExtCount = 0;
  
  var cache = CacheService.getScriptCache();
  
  attachments.forEach(function(attachment) {
    // Strip whitespace tricks: "invoice.pdf .exe" -> "invoice.pdf.exe"
    var name = attachment.getName().toLowerCase().replace(/\s+/g, "");
    var parts = name.split(".");
    var ext = parts.length > 1 ? parts.pop() : "";
    
    // Check: Dangerous file extension
    if (dangerousExtensions.includes(ext)) {
      dangerousCount++;
    }
    
    // Check: Suspicious archive/macro extension
    if (suspiciousExtensions.includes(ext)) {
      suspiciousCount++;
    }
    
    // Check: Double extension (e.g., invoice.pdf.exe or test.docm.pdf)
    if (parts.length > 1) {
      var allExtensions = parts.slice(1);
      allExtensions.push(ext); // add back the final extension
      var hasDangerous = allExtensions.some(function(e) {
        return dangerousExtensions.includes(e) || suspiciousExtensions.includes(e);
      });
      var hasInnocent = allExtensions.some(function(e) {
        return ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"].includes(e);
      });
      if (hasDangerous && hasInnocent) {
        doubleExtCount++;
      }
    }
    
    // Check: VirusTotal hash lookup (skip files > 5MB)
    if (attachment.getSize() > 5 * 1024 * 1024) {
      signals.push("ℹ️ Large attachment skipped from VT scan: " + name);
      return;
    }
    
    try {
      var hash = computeSHA256(attachment.getBytes());
      
      // Check cache first
      var cached = cache.get("vt_hash_" + hash);
      var vtResult;
      if (cached) {
        vtResult = JSON.parse(cached);
      } else {
        vtResult = checkFileHash(hash);
        cache.put("vt_hash_" + hash, JSON.stringify(vtResult), 21600);
      }
      
      if (vtResult.malicious > 5) {
        signals.push("🚨 VT: Attachment \"" + name + "\" flagged by " + vtResult.malicious + " engines");
        score += 30;
      } else if (vtResult.malicious >= 2) {
        signals.push("⚠️ VT: Attachment \"" + name + "\" flagged by " + vtResult.malicious + " engines");
        score += 15;
      }
    } catch (err) {
      // Hash check failed - skip silently
    }
  });
  
  if (dangerousCount > 0) {
    score += 30;
    signals.push("🚨 " + dangerousCount + " dangerous file type(s) attached");
  }
  
  if (doubleExtCount > 0) {
    score += 25;
    signals.push("🚨 " + doubleExtCount + " attachment(s) with double extension");
  }
  
  if (suspiciousCount > 0) {
    score += 10;
    signals.push("⚠️ " + suspiciousCount + " suspicious file type(s) attached (archive/macro-enabled)");
  }
  
  return { score: score, signals: signals };
}

// --- VirusTotal Integration ---

function checkVirusTotal(urls) {
  var score = 0;
  var signals = [];
  var apiKey = getApiKey();
  
  if (!apiKey || urls.length === 0) {
    return { score: score, signals: signals };
  }
  
  var cache = CacheService.getScriptCache();
  var urlsToCheck = urls.slice(0, 5);
  
  urlsToCheck.forEach(function(url) {
    try {
      var urlId = Utilities.base64Encode(url).replace(/=+$/, "");
      
      // Check cache first
      var cached = cache.get("vt_url_" + urlId);
      var malicious, suspicious;
      
      if (cached) {
        var cachedData = JSON.parse(cached);
        malicious = cachedData.malicious;
        suspicious = cachedData.suspicious;
      } else {
        var response = UrlFetchApp.fetch(
          "https://www.virustotal.com/api/v3/urls/" + urlId,
          {
            method: "GET",
            headers: { "x-apikey": apiKey },
            muteHttpExceptions: true
          }
        );
        
        var code = response.getResponseCode();
        if (code !== 200) return;
        
        var data = JSON.parse(response.getContentText());
        var stats = data.data.attributes.last_analysis_stats;
        malicious = stats.malicious || 0;
        suspicious = stats.suspicious || 0;
        
        cache.put("vt_url_" + urlId, JSON.stringify({ malicious: malicious, suspicious: suspicious }), 21600);
      }
      
      if (malicious > 5) {
        score += 30;
        signals.push("🚨 VT: " + url.substring(0, 50) + " flagged by " + malicious + " engines");
      } else if (malicious >= 2 || suspicious >= 3) {
        score += 15;
        signals.push("⚠️ VT: " + url.substring(0, 50) + " flagged by " + (malicious + suspicious) + " engines");
      }
      
    } catch (err) {
      // API error - skip silently
    }
  });
  
  return { score: score, signals: signals };
}

function computeSHA256(bytes) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  return digest.map(function(byte) {
    var hex = (byte < 0 ? byte + 256 : byte).toString(16);
    return hex.length === 1 ? "0" + hex : hex;
  }).join("");
}

function checkFileHash(hash) {
  var apiKey = getApiKey();
  
  if (!apiKey) {
    return { malicious: 0 };
  }
  
  try {
    var response = UrlFetchApp.fetch(
      "https://www.virustotal.com/api/v3/files/" + hash,
      {
        method: "GET",
        headers: { "x-apikey": apiKey },
        muteHttpExceptions: true
      }
    );
    
    var code = response.getResponseCode();
    if (code !== 200) {
      return { malicious: 0 };
    }
    
    var data = JSON.parse(response.getContentText());
    var stats = data.data.attributes.last_analysis_stats;
    return { malicious: stats.malicious || 0 };
    
  } catch (err) {
    return { malicious: 0 };
  }
}

// --- Verdict ---

function getVerdict(score) {
  if (score >= 60) {
    return { label: "Malicious", color: "#D32F2F" };
  } else if (score >= 30) {
    return { label: "Suspicious", color: "#F57C00" };
  } else {
    return { label: "Safe", color: "#388E3C" };
  }
}

// --- UI Card Builder ---

function buildResultCard(score, verdict, signals, from, subject) {
  var header = CardService.newCardHeader()
    .setTitle("Email Threat Score")
    .setSubtitle(subject);
  
  // Score and verdict section
  var scoreSection = CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setText("<b>Score: " + score + "/100</b>")
      .setTopLabel("Risk Assessment"))
    .addWidget(CardService.newDecoratedText()
      .setText("<font color='" + verdict.color + "'><b>" + verdict.label + "</b></font>")
      .setTopLabel("Verdict"))
    .addWidget(CardService.newDecoratedText()
      .setText(from)
      .setTopLabel("Sender"));
  
  // Signals section
  var signalsSection = CardService.newCardSection()
    .setHeader("Findings");
  
  if (signals.length === 0) {
    signalsSection.addWidget(CardService.newTextParagraph()
      .setText("✅ No suspicious signals detected."));
  } else {
    signals.forEach(function(signal) {
      signalsSection.addWidget(CardService.newTextParagraph()
        .setText(signal));
    });
  }
  
  // Actions section
  var actionSection = CardService.newCardSection()
    .setHeader("Actions");
  
  var sender = extractEmailParts(from);
  
  actionSection.addWidget(CardService.newTextButton()
    .setText("🚫 Blacklist Sender")
    .setOnClickAction(CardService.newAction()
      .setFunctionName("addToBlacklist")
      .setParameters({ "entry": sender.email })));
  
  actionSection.addWidget(CardService.newTextButton()
    .setText("🚫 Blacklist Domain")
    .setOnClickAction(CardService.newAction()
      .setFunctionName("addToBlacklist")
      .setParameters({ "entry": sender.domain })));
  
  actionSection.addWidget(CardService.newTextButton()
    .setText("📋 Manage Blacklist")
    .setOnClickAction(CardService.newAction()
      .setFunctionName("showBlacklistManager")));
  
  var card = CardService.newCardBuilder()
    .setHeader(header)
    .addSection(scoreSection)
    .addSection(signalsSection)
    .addSection(actionSection)
    .build();
  
  return [card];
}

// --- Blacklist Management ---

function addToBlacklist(e) {
  var entry = e.parameters.entry.toLowerCase().trim();
  var props = PropertiesService.getUserProperties();
  var blacklistRaw = props.getProperty("blacklist");
  var blacklist = blacklistRaw ? JSON.parse(blacklistRaw) : [];
  
  if (!blacklist.includes(entry)) {
    blacklist.push(entry);
    props.setProperty("blacklist", JSON.stringify(blacklist));
  }
  
  var nav = CardService.newNavigation()
    .pushCard(CardService.newCardBuilder()
      .addSection(CardService.newCardSection()
        .addWidget(CardService.newTextParagraph()
          .setText("✅ Added to blacklist: " + entry)))
      .build());
  
  return CardService.newActionResponseBuilder()
    .setNavigation(nav)
    .build();
}

function showBlacklistManager() {
  var props = PropertiesService.getUserProperties();
  var blacklistRaw = props.getProperty("blacklist");
  var blacklist = blacklistRaw ? JSON.parse(blacklistRaw) : [];
  
  var section = CardService.newCardSection()
    .setHeader("Your Blacklist (" + blacklist.length + " entries)");
  
  if (blacklist.length === 0) {
    section.addWidget(CardService.newTextParagraph()
      .setText("Your blacklist is empty."));
  } else {
    blacklist.forEach(function(entry) {
      section.addWidget(CardService.newDecoratedText()
        .setText(entry)
        .setButton(CardService.newTextButton()
          .setText("Remove")
          .setOnClickAction(CardService.newAction()
            .setFunctionName("removeFromBlacklist")
            .setParameters({ "entry": entry }))));
    });
  }
  
  // Add manual entry
  var addSection = CardService.newCardSection()
    .setHeader("Add Entry");
  
  addSection.addWidget(CardService.newTextInput()
    .setFieldName("newEntry")
    .setTitle("Email or domain")
    .setHint("e.g. spam@evil.com or evil.com"));
  
  addSection.addWidget(CardService.newTextButton()
    .setText("Add to Blacklist")
    .setOnClickAction(CardService.newAction()
      .setFunctionName("addManualBlacklistEntry")));
  
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Blacklist Manager"))
    .addSection(section)
    .addSection(addSection)
    .build();
  
  var nav = CardService.newNavigation().pushCard(card);
  return CardService.newActionResponseBuilder()
    .setNavigation(nav)
    .build();
}

function removeFromBlacklist(e) {
  var entryToRemove = e.parameters.entry.toLowerCase().trim();
  var props = PropertiesService.getUserProperties();
  var blacklistRaw = props.getProperty("blacklist");
  var blacklist = blacklistRaw ? JSON.parse(blacklistRaw) : [];
  
  blacklist = blacklist.filter(function(entry) {
    return entry.toLowerCase() !== entryToRemove;
  });
  
  props.setProperty("blacklist", JSON.stringify(blacklist));
  
  var nav = CardService.newNavigation().popCard();
  return CardService.newActionResponseBuilder()
    .setNavigation(nav)
    .build();
}

function addManualBlacklistEntry(e) {
  var newEntry = e.formInput.newEntry;
  
  if (!newEntry || newEntry.trim() === "") {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification()
        .setText("Please enter an email or domain."))
      .build();
  }
  
  newEntry = newEntry.toLowerCase().trim();
  var props = PropertiesService.getUserProperties();
  var blacklistRaw = props.getProperty("blacklist");
  var blacklist = blacklistRaw ? JSON.parse(blacklistRaw) : [];
  
  if (blacklist.includes(newEntry)) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification()
        .setText("\"" + newEntry + "\" is already in your blacklist."))
      .build();
  }
  
  blacklist.push(newEntry);
  props.setProperty("blacklist", JSON.stringify(blacklist));
  
  var nav = CardService.newNavigation().popCard();
  return CardService.newActionResponseBuilder()
    .setNavigation(nav)
    .setNotification(CardService.newNotification()
      .setText("✅ Added: " + newEntry))
    .build();
}

function checkBlacklist(from) {
  var score = 0;
  var signals = [];
  
  var sender = extractEmailParts(from);
  
  var props = PropertiesService.getUserProperties();
  var blacklistRaw = props.getProperty("blacklist");
  var blacklist = blacklistRaw ? JSON.parse(blacklistRaw) : [];
  
  blacklist.some(function(entry) {
    entry = entry.toLowerCase();
    if (sender.email === entry) {
      score += 50;
      signals.push("🚫 Sender email is on your blacklist: " + sender.email);
      return true;
    } else if (sender.domain === entry || sender.domain.endsWith("." + entry)) {
      score += 50;
      signals.push("🚫 Sender domain is on your blacklist: " + sender.domain);
      return true;
    }
    return false;
  });
  
  return { score: score, signals: signals };
}
