const categories = {
  ALL: "All Modules",
  DORKS: "Google Dorks",
  RECON: "Recon & Subdomains",
  ARCHIVES: "Archives & History",
  INTEL: "OSINT & Intelligence",
  FILES: "Specific Files",
};

const categoryCodes = {
  DORKS: "GD",
  RECON: "RC",
  ARCHIVES: "WB",
  INTEL: "OS",
  FILES: "FL",
};

const storageKey = "osint-helper-state";

const googleSearch = (query) =>
  `https://www.google.com/search?q=${encodeURIComponent(query)}`;

const yandexSearch = (query) =>
  `https://yandex.com/search/?text=${encodeURIComponent(query)}`;

const githubSearch = (query, type = "code") =>
  `https://github.com/search?q=${encodeURIComponent(query)}&type=${encodeURIComponent(type)}`;

const unique = (items) => [...new Set(items.filter(Boolean))];

const normalizeSpaces = (value) => value.trim().replace(/\s+/g, " ");

const quote = (value) => `"${String(value).replace(/"/g, "").trim()}"`;

const modeLabels = {
  domain: "domain",
  keyword: "keyword",
  analytics: "analytics",
};

const slugify = (value) =>
  String(value)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

const sanitizeTarget = (value) =>
  normalizeSpaces(value)
    .replace(/^[a-z]+:\/\//i, "")
    .replace(/^www\./i, "")
    .replace(/[/?#].*$/, "");

function looksLikeDomain(value) {
  return /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(sanitizeTarget(value));
}

function getDomainFamily(hostname) {
  const segments = hostname.split(".").filter(Boolean);

  if (segments.length < 2) {
    return {
      bare: hostname,
      secondLevel: hostname,
      registrable: hostname,
    };
  }

  const hasCountryCodeSuffix =
    segments.length >= 3 &&
    segments.at(-1).length === 2 &&
    segments.at(-2).length <= 3;

  const registrableParts = hasCountryCodeSuffix
    ? segments.slice(-3)
    : segments.slice(-2);

  const bareIndex = hasCountryCodeSuffix ? segments.length - 3 : segments.length - 2;
  const bare = segments[bareIndex];
  const secondLevel = hasCountryCodeSuffix
    ? segments.slice(-3, -1).join(".")
    : registrableParts.join(".");

  return {
    bare,
    secondLevel,
    registrable: registrableParts.join("."),
  };
}

function buildTargetContext(input) {
  const raw = normalizeSpaces(input || "");
  const domainTarget = looksLikeDomain(raw) ? sanitizeTarget(raw).toLowerCase() : "";
  const family = domainTarget ? getDomainFamily(domainTarget) : null;

  const keywordVariants = family
    ? unique([domainTarget, family.bare])
    : raw
      ? [raw]
      : [];

  const keywordExpression =
    keywordVariants.length > 1
      ? `(${keywordVariants.map(quote).join(" OR ")})`
      : keywordVariants.length === 1
        ? quote(keywordVariants[0])
        : quote("target");

  const nameTarget = family ? family.bare : raw;
  const organizationSlug = slugify(nameTarget || "example");

  return {
    raw,
    domainTarget,
    hasDomain: Boolean(domainTarget),
    hasKeyword: Boolean(raw),
    nameTarget,
    keywordVariants,
    keywordExpression,
    organizationSlug,
  };
}

function buildAnalyticsContext(input) {
  const raw = normalizeSpaces(input || "");
  const normalized = raw
    .toUpperCase()
    .replace(/\s+/g, "")
    .replace(/_/g, "-")
    .replace(/[^A-Z0-9-]/g, "")
    .replace(/--+/g, "-")
    .replace(/^-+|-+$/g, "");

  const match = normalized.match(/^UA-?(\d+)(?:-?(\d+))?$/i);

  if (!match) {
    const genericMatch = normalized.match(/^([A-Z]{1,10})-([A-Z0-9]+(?:-[A-Z0-9]+)*)$/);

    if (!genericMatch) {
      return {
        analyticsRaw: raw,
        hasAnalyticsInput: Boolean(raw),
        hasAnalyticsTag: false,
        analyticsCanonical: "",
        analyticsCompact: "",
        analyticsTagId: "",
        analyticsType: "",
      };
    }

    const analyticsType = genericMatch[1];
    const analyticsBody = genericMatch[2];
    const analyticsCanonical = `${analyticsType}-${analyticsBody}`;
    const analyticsCompact = `${analyticsType}${analyticsBody.replace(/-/g, "")}`;

    return {
      analyticsRaw: raw,
      hasAnalyticsInput: true,
      hasAnalyticsTag: true,
      analyticsCanonical,
      analyticsCompact,
      analyticsTagId: analyticsCanonical,
      analyticsType,
    };
  }

  const accountId = match[1];
  const profileId = match[2] || "";
  const analyticsCanonical = `UA-${accountId}${profileId ? `-${profileId}` : ""}`;
  const analyticsCompact = `UA${accountId}`;

  return {
    analyticsRaw: raw,
    hasAnalyticsInput: true,
    hasAnalyticsTag: true,
    analyticsCanonical,
    analyticsCompact,
    analyticsTagId: analyticsCanonical,
    analyticsType: "UA",
  };
}

function buildContext() {
  return {
    ...buildTargetContext(state.target),
    ...buildAnalyticsContext(state.analytics),
  };
}

function buildGoogleKeywordSiteQuery(siteRule, context) {
  return `${siteRule} ${context.keywordExpression}`;
}

function domainGoogleTool(id, title, category, note, queryBuilder) {
  return {
    id,
    title,
    category,
    provider: "Google",
    mode: "domain",
    note,
    buildHint: (context) => queryBuilder(context.domainTarget || "example.com"),
    buildUrl: (context) => googleSearch(queryBuilder(context.domainTarget)),
  };
}

function keywordGoogleTool(id, title, category, note, queryBuilder) {
  return {
    id,
    title,
    category,
    provider: "Google",
    mode: "keyword",
    note,
    buildHint: (context) => queryBuilder(context),
    buildUrl: (context) => googleSearch(queryBuilder(context)),
  };
}

const domainTools = [
  domainGoogleTool(
    1,
    "Directory Listing",
    "DORKS",
    "Looks for open directory listing pages.",
    (target) => `site:${target} intitle:index.of`
  ),
  domainGoogleTool(
    2,
    "Exposed Configs",
    "DORKS",
    "Searches for exposed configuration files.",
    (target) =>
      `site:${target} (ext:xml OR ext:conf OR ext:cnf OR ext:reg OR ext:inf OR ext:rdp OR ext:cfg OR ext:txt OR ext:ora OR ext:ini)`
  ),
  domainGoogleTool(
    3,
    "DB Files",
    "DORKS",
    "Looks for indexed database dumps and files.",
    (target) => `site:${target} (ext:sql OR ext:dbf OR ext:mdb)`
  ),
  domainGoogleTool(
    4,
    "Log Files",
    "DORKS",
    "Finds indexed log files.",
    (target) => `site:${target} ext:log`
  ),
  domainGoogleTool(
    5,
    "Backup Files",
    "DORKS",
    "Looks for accessible backup copies.",
    (target) => `site:${target} (ext:bkf OR ext:bkp OR ext:bak OR ext:old OR ext:backup)`
  ),
  domainGoogleTool(
    6,
    "Login Pages",
    "DORKS",
    "Searches for indexed login pages.",
    (target) => `site:${target} inurl:login`
  ),
  domainGoogleTool(
    7,
    "SQL Errors",
    "DORKS",
    "Tries to locate public SQL error messages.",
    (target) =>
      `site:${target} ("sql syntax near" OR "syntax error has occurred" OR "incorrect syntax near" OR "unexpected end of SQL command" OR "Warning: mysql_connect()" OR "Warning: mysql_query()" OR "Warning: pg_connect()")`
  ),
  domainGoogleTool(
    8,
    "Public Documents",
    "DORKS",
    "Looks for publicly indexed documents.",
    (target) =>
      `site:${target} (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:sxw OR ext:psw OR ext:ppt OR ext:pptx OR ext:pps OR ext:csv)`
  ),
  domainGoogleTool(
    9,
    "phpinfo()",
    "DORKS",
    "Looks for public phpinfo pages.",
    (target) => `site:${target} ext:php intitle:phpinfo "published by the PHP Group"`
  ),
  domainGoogleTool(
    10,
    "Shells / Backdoors",
    "DORKS",
    "Searches for names and artifacts commonly tied to webshells.",
    (target) =>
      `site:${target} (inurl:shell OR inurl:backdoor OR inurl:wso OR inurl:cmd OR shadow OR passwd OR boot.ini)`
  ),
  domainGoogleTool(
    11,
    "Open Redirects",
    "DORKS",
    "Looks for indexed redirect parameters.",
    (target) =>
      `site:${target} (inurl:redir OR inurl:url OR inurl:redirect OR inurl:return OR inurl:src=http OR inurl:r=http)`
  ),
  domainGoogleTool(
    12,
    "Struts RCE",
    "DORKS",
    "Searches for legacy Struts endpoints.",
    (target) => `site:${target} (ext:action OR ext:struts OR ext:do)`
  ),
  domainGoogleTool(
    13,
    "WordPress Files",
    "DORKS",
    "Looks for common WordPress install paths.",
    (target) => `site:${target} (inurl:wp-content OR inurl:wp-includes OR inurl:wp-upload)`
  ),
  domainGoogleTool(
    14,
    "Git Exposed",
    "DORKS",
    "Searches for exposed Git directories outside GitHub.",
    (target) => `site:${target} (inurl:".git" OR inurl:".gitignore") -github`
  ),
  domainGoogleTool(
    15,
    "GitLab Config",
    "DORKS",
    "Looks for GitLab-related configuration files.",
    (target) => `site:${target} ("gitlab.yml" OR "database.yml") "private"`
  ),
  domainGoogleTool(
    16,
    "ENV Files",
    "DORKS",
    "Searches for indexed .env files.",
    (target) => `site:${target} (filename:.env OR filename:.env.local)`
  ),
  domainGoogleTool(
    17,
    "Htaccess / Info",
    "DORKS",
    "Looks for indexed phpinfo.php and .htaccess files.",
    (target) => `site:${target} (inurl:"/phpinfo.php" OR inurl:".htaccess")`
  ),
  domainGoogleTool(
    18,
    "Install / Setup",
    "DORKS",
    "Tries to locate install and setup pages.",
    (target) => `site:${target} (inurl:readme OR inurl:license OR inurl:install OR inurl:setup OR inurl:config)`
  ),
  domainGoogleTool(
    21,
    "Pastebin Dumps",
    "INTEL",
    "Searches the domain inside public Pastebin dumps.",
    (target) => `site:pastebin.com ${target}`
  ),
  domainGoogleTool(
    22,
    "LinkedIn Employees",
    "INTEL",
    "Searches for employee mentions and related pages.",
    (target) => `site:linkedin.com employees ${target}`
  ),
  {
    id: 23,
    title: "GitHub Source",
    category: "INTEL",
    provider: "GitHub",
    mode: "domain",
    note: "Opens a GitHub code search using the domain.",
    buildHint: (context) => quote(context.domainTarget || "example.com"),
    buildUrl: (context) => githubSearch(quote(context.domainTarget), "code"),
  },
  {
    id: 24,
    title: "ThreatCrowd",
    category: "INTEL",
    provider: "ThreatCrowd",
    mode: "domain",
    note: "Direct domain lookup shortcut.",
    buildHint: (context) => `domain=${context.domainTarget || "example.com"}`,
    buildUrl: (context) =>
      `http://threatcrowd.org/domain.php?domain=${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 25,
    title: "OpenBugBounty",
    category: "INTEL",
    provider: "OpenBugBounty",
    mode: "domain",
    note: "Searches for public host records.",
    buildHint: (context) => `search=${context.domainTarget || "example.com"}&type=host`,
    buildUrl: (context) =>
      `https://www.openbugbounty.org/search/?search=${encodeURIComponent(context.domainTarget)}&type=host`,
  },
  {
    id: 26,
    title: "Reddit Mentions",
    category: "INTEL",
    provider: "Reddit",
    mode: "domain",
    note: "Searches recent Reddit mentions of the domain.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) =>
      `https://www.reddit.com/search/?q=${encodeURIComponent(context.domainTarget)}&source=recent`,
  },
  {
    id: 27,
    title: "Censys (IPv4)",
    category: "INTEL",
    provider: "Censys",
    mode: "domain",
    note: "Legacy IPv4 lookup in Censys.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) =>
      `https://censys.io/ipv4?q=${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 28,
    title: "Censys (Domains)",
    category: "INTEL",
    provider: "Censys",
    mode: "domain",
    note: "Legacy domain lookup in Censys.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) =>
      `https://censys.io/domain?q=${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 29,
    title: "Censys (Certs)",
    category: "INTEL",
    provider: "Censys",
    mode: "domain",
    note: "Legacy certificate lookup in Censys.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) =>
      `https://censys.io/certificates?q=${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 30,
    title: "Shodan Search",
    category: "INTEL",
    provider: "Shodan",
    mode: "domain",
    note: "Opens a Shodan search for the provided host.",
    buildHint: (context) => `hostname:${context.domainTarget || "example.com"}`,
    buildUrl: (context) =>
      `https://www.shodan.io/search?query=${encodeURIComponent(`hostname:${context.domainTarget}`)}`,
  },
  {
    id: 53,
    title: "ARIN Whois",
    category: "INTEL",
    provider: "ARIN",
    mode: "keyword",
    note: "Searches ARIN Whois using the bare domain name or keyword.",
    buildHint: (context) => context.nameTarget || "example",
    buildUrl: (context) =>
      `https://whois.arin.net/ui/?q=${encodeURIComponent(context.nameTarget)}`,
  },
  {
    id: 54,
    title: "ThreatMiner",
    category: "INTEL",
    provider: "ThreatMiner",
    mode: "domain",
    note: "Runs a domain lookup in ThreatMiner.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) =>
      `https://www.threatminer.org/domain.php?q=${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 57,
    title: "AlienVault OTX",
    category: "INTEL",
    provider: "AlienVault",
    mode: "domain",
    note: "Open the domain indicator and inspect the Associated URLs section.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) =>
      `https://otx.alienvault.com/indicator/domain/${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 55,
    title: "GrayHatWarfare",
    category: "INTEL",
    provider: "GrayHatWarfare",
    mode: "keyword",
    note: "Searches exposed bucket files using the bare domain name or keyword.",
    buildHint: (context) => context.nameTarget || "example",
    buildUrl: (context) =>
      `https://buckets.grayhatwarfare.com/files?keywords=${encodeURIComponent(context.nameTarget)}&page=1`,
  },
  domainGoogleTool(
    31,
    "Find Subdomains",
    "RECON",
    "Searches for subdomains through Google.",
    (target) => `site:*.${target}`
  ),
  domainGoogleTool(
    32,
    "Deep Subdomains",
    "RECON",
    "Searches for deeper-level subdomains.",
    (target) => `site:*.*.${target}`
  ),
  {
    id: 33,
    title: "Crt.sh (Certificates)",
    category: "RECON",
    provider: "crt.sh",
    mode: "domain",
    note: "Searches certificate records for the domain.",
    buildHint: (context) => `%25.${context.domainTarget || "example.com"}`,
    buildUrl: (context) =>
      `https://crt.sh/?q=${encodeURIComponent(`%.${context.domainTarget}`)}`,
  },
  {
    id: 56,
    title: "BGP HE Search",
    category: "RECON",
    provider: "BGP HE",
    mode: "keyword",
    note: "Searches BGP HE using the bare domain name or keyword.",
    buildHint: (context) => context.nameTarget || "example",
    buildUrl: (context) =>
      `https://bgp.he.net/search?search%5Bsearch%5D=${encodeURIComponent(context.nameTarget)}&commit=Search`,
  },
  {
    id: 58,
    title: "Find ASN",
    category: "RECON",
    provider: "BGP.Tools",
    mode: "domain",
    note: "Resolve the domain through BGP.Tools DNS to ASN lookup.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) => `https://bgp.tools/dns/${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 34,
    title: "Wayback SWF",
    category: "FILES",
    provider: "Wayback",
    mode: "domain",
    note: "Lists archived SWF files for the domain.",
    buildHint: (context) =>
      `url=${context.domainTarget || "example.com"}/&filter=urlkey:.*swf`,
    buildUrl: (context) =>
      `https://web.archive.org/cdx/search?url=${encodeURIComponent(`${context.domainTarget}/`)}&matchType=domain&collapse=urlkey&output=text&fl=original&filter=urlkey:.*swf&limit=100000&_=1507209148310`,
  },
  {
    id: 35,
    title: "Wayback MIME SWF",
    category: "FILES",
    provider: "Wayback",
    mode: "domain",
    note: "Filters archived SWFs by MIME type.",
    buildHint: (context) =>
      `url=${context.domainTarget || "example.com"}/&filter=mimetype:application/x-shockwave-flash`,
    buildUrl: (context) =>
      `https://web.archive.org/cdx/search?url=${encodeURIComponent(`${context.domainTarget}/`)}&matchType=domain&collapse=urlkey&output=text&fl=original&filter=mimetype:application/x-shockwave-flash&limit=100000&_=1507209148310`,
  },
  {
    id: 36,
    title: "Wayback Domain",
    category: "ARCHIVES",
    provider: "Wayback",
    mode: "domain",
    note: "Opens the main Wayback history for the domain.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) => `https://web.archive.org/web/*/${context.domainTarget}`,
  },
  {
    id: 37,
    title: "Wayback Full",
    category: "ARCHIVES",
    provider: "Wayback",
    mode: "domain",
    note: "Full archive history including internal paths.",
    buildHint: (context) => `${context.domainTarget || "example.com"}/*`,
    buildUrl: (context) => `https://web.archive.org/web/*/${context.domainTarget}/*`,
  },
  {
    id: 38,
    title: "Wayback WP",
    category: "ARCHIVES",
    provider: "Wayback",
    mode: "domain",
    note: "Filters WordPress-related items in the Internet Archive CDX.",
    buildHint: (context) =>
      `url=${context.domainTarget || "example.com"}/&filter=urlkey:.*wp[-].*`,
    buildUrl: (context) =>
      `http://wwwb-dedup.us.archive.org:8083/cdx/search?url=${encodeURIComponent(`${context.domainTarget}/`)}&matchType=domain&collapse=digest&output=text&fl=original,timestamp&filter=urlkey:.*wp[-].*&limit=1000000&xx=`,
  },
  {
    id: 39,
    title: "Crossdomain.xml",
    category: "FILES",
    provider: "Direct",
    mode: "domain",
    note: "Opens the host crossdomain.xml directly.",
    buildHint: (context) => `http://${context.domainTarget || "example.com"}/crossdomain.xml`,
    buildUrl: (context) => `http://${context.domainTarget}/crossdomain.xml`,
  },
  domainGoogleTool(
    40,
    "SWF (Google)",
    "FILES",
    "Searches for SWF files through Google.",
    (target) => `inurl:${target} ext:swf`
  ),
  {
    id: 41,
    title: "SWF (Yandex)",
    category: "FILES",
    provider: "Yandex",
    mode: "domain",
    note: "Searches for SWF files through Yandex.",
    buildHint: (context) => `site:${context.domainTarget || "example.com"} mime:swf`,
    buildUrl: (context) => yandexSearch(`site:${context.domainTarget} mime:swf`),
  },
  {
    id: 42,
    title: "VirusTotal",
    category: "INTEL",
    provider: "VirusTotal",
    mode: "domain",
    note: "Domain page inside VirusTotal.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) => `https://www.virustotal.com/gui/domain/${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 43,
    title: "Urlscan.io",
    category: "INTEL",
    provider: "urlscan.io",
    mode: "domain",
    note: "Domain search inside urlscan.",
    buildHint: (context) => `domain:${context.domainTarget || "example.com"}`,
    buildUrl: (context) => `https://urlscan.io/search/#domain:${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 44,
    title: "Wappalyzer",
    category: "INTEL",
    provider: "Wappalyzer",
    mode: "domain",
    note: "Technology lookup for the domain.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) => `https://www.wappalyzer.com/lookup/${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 45,
    title: "Security Headers",
    category: "RECON",
    provider: "SecurityHeaders",
    mode: "domain",
    note: "Opens the security headers analysis.",
    buildHint: (context) => `q=${context.domainTarget || "example.com"}`,
    buildUrl: (context) =>
      `https://securityheaders.com/?q=${encodeURIComponent(context.domainTarget)}&followRedirects=on`,
  },
  {
    id: 46,
    title: "BuiltWith",
    category: "INTEL",
    provider: "BuiltWith",
    mode: "domain",
    note: "Research the Relationships tab to map related sites through shared analytics and tracking codes.",
    buildHint: (context) => `relationships/${context.domainTarget || "example.com"}`,
    buildUrl: (context) => `https://builtwith.com/relationships/${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 47,
    title: "SSL Labs",
    category: "RECON",
    provider: "SSL Labs",
    mode: "domain",
    note: "SSL evaluation for the provided host.",
    buildHint: (context) => `d=${context.domainTarget || "example.com"}`,
    buildUrl: (context) =>
      `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 48,
    title: "Censys Platform",
    category: "INTEL",
    provider: "Censys",
    mode: "domain",
    note: "Direct search in the modern Censys platform.",
    buildHint: (context) => quote(context.domainTarget || "example.com"),
    buildUrl: (context) =>
      `https://platform.censys.io/search?q=${encodeURIComponent(quote(context.domainTarget))}`,
  },
  {
    id: 49,
    title: "PublicWWW",
    category: "INTEL",
    provider: "PublicWWW",
    mode: "domain",
    note: "Searches for code and references tied to the domain.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) => `https://publicwww.com/websites/${encodeURIComponent(context.domainTarget)}/`,
  },
  {
    id: 50,
    title: "ZoomEye",
    category: "INTEL",
    provider: "ZoomEye",
    mode: "domain",
    note: "Domain search inside ZoomEye.",
    buildHint: (context) => context.domainTarget || "example.com",
    buildUrl: (context) => `https://www.zoomeye.ai/searchResult?q=${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 51,
    title: "Jina AI",
    category: "INTEL",
    provider: "Jina AI",
    mode: "domain",
    note: "Resolves the host through r.jina.ai.",
    buildHint: (context) => `https://r.jina.ai/${context.domainTarget || "example.com"}`,
    buildUrl: (context) => `https://r.jina.ai/${encodeURIComponent(context.domainTarget)}`,
  },
  {
    id: 52,
    title: "Wayback URL Keys",
    category: "ARCHIVES",
    provider: "Wayback",
    mode: "domain",
    note: "Wildcard CDX search for archived domain paths.",
    buildHint: (context) =>
      `*.${context.domainTarget || "example.com"}/* -> original`,
    buildUrl: (context) =>
      `http://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(`*.${context.domainTarget}/*`)}&output=text&fl=original&collapse=urlkey`,
  },
];

const keywordTools = [
  keywordGoogleTool(
    101,
    "Codepad",
    "INTEL",
    "Searches mentions inside Codepad snippets.",
    (context) => buildGoogleKeywordSiteQuery("site:codepad.co", context)
  ),
  keywordGoogleTool(
    102,
    "Scribd",
    "INTEL",
    "Looks for mentions inside Scribd documents.",
    (context) => buildGoogleKeywordSiteQuery("site:scribd.com", context)
  ),
  keywordGoogleTool(
    103,
    "NodeJS Source",
    "INTEL",
    "Looks for mentions on npmjs.",
    (context) => buildGoogleKeywordSiteQuery("site:npmjs.com", context)
  ),
  keywordGoogleTool(
    104,
    "RunKit",
    "INTEL",
    "Looks for mentions on npm.runkit.",
    (context) => buildGoogleKeywordSiteQuery("site:npm.runkit.com", context)
  ),
  keywordGoogleTool(
    105,
    "Libraries.io",
    "INTEL",
    "Looks for mentions in indexed packages and projects.",
    (context) => buildGoogleKeywordSiteQuery("site:libraries.io", context)
  ),
  keywordGoogleTool(
    106,
    "Coggle",
    "INTEL",
    "Searches public mind maps tied to the target.",
    (context) => buildGoogleKeywordSiteQuery("site:coggle.it", context)
  ),
  keywordGoogleTool(
    107,
    "Papaly",
    "INTEL",
    "Looks for public bookmarks related to the target.",
    (context) => buildGoogleKeywordSiteQuery("site:papaly.com", context)
  ),
  keywordGoogleTool(
    108,
    "Trello",
    "INTEL",
    "Searches public Trello boards.",
    (context) => buildGoogleKeywordSiteQuery("site:trello.com", context)
  ),
  keywordGoogleTool(
    109,
    "Prezi",
    "INTEL",
    "Looks for public Prezi presentations.",
    (context) => buildGoogleKeywordSiteQuery("site:prezi.com", context)
  ),
  keywordGoogleTool(
    110,
    "jsDelivr",
    "INTEL",
    "Searches for references in files served by the CDN.",
    (context) => buildGoogleKeywordSiteQuery("site:jsdelivr.net", context)
  ),
  keywordGoogleTool(
    111,
    "CodePen",
    "INTEL",
    "Looks for public examples and snippets on CodePen.",
    (context) => buildGoogleKeywordSiteQuery("site:codepen.io", context)
  ),
  keywordGoogleTool(
    112,
    "Pastebin",
    "INTEL",
    "Searches Pastebin mentions by keyword or domain variants.",
    (context) => buildGoogleKeywordSiteQuery("site:pastebin.com", context)
  ),
  keywordGoogleTool(
    113,
    "Repl.it",
    "INTEL",
    "Looks for mentions in public Repl projects.",
    (context) => buildGoogleKeywordSiteQuery("site:repl.it", context)
  ),
  keywordGoogleTool(
    114,
    "Gitter",
    "INTEL",
    "Searches indexed public conversations on Gitter.",
    (context) => buildGoogleKeywordSiteQuery("site:gitter.im", context)
  ),
  keywordGoogleTool(
    115,
    "Bitbucket",
    "INTEL",
    "Looks for indexed repositories and snippets.",
    (context) => buildGoogleKeywordSiteQuery("site:bitbucket.org", context)
  ),
  keywordGoogleTool(
    116,
    "Atlassian",
    "INTEL",
    "Searches Atlassian workspaces indexed by Google.",
    (context) => buildGoogleKeywordSiteQuery("site:*.atlassian.net", context)
  ),
  {
    id: 119,
    title: "GitHub Code Search",
    category: "INTEL",
    provider: "GitHub",
    mode: "keyword",
    note: "Searches GitHub code by keyword or domain variants.",
    buildHint: (context) => context.keywordExpression,
    buildUrl: (context) =>
      githubSearch(
        context.keywordVariants.length > 1
          ? context.keywordVariants.map(quote).join(" OR ")
          : quote(context.keywordVariants[0]),
        "code"
      ),
  },
  keywordGoogleTool(
    117,
    "GitLab",
    "INTEL",
    "Looks for indexed GitLab instances and pages.",
    (context) => `inurl:gitlab ${context.keywordExpression}`
  ),
  keywordGoogleTool(
    118,
    "Find S3 Buckets",
    "RECON",
    "Searches public S3 buckets related to the target.",
    (context) => buildGoogleKeywordSiteQuery("site:.s3.amazonaws.com", context)
  ),
];

const analyticsTools = [
  {
    id: 120,
    title: "Google Tag Manager JS",
    category: "INTEL",
    provider: "Google Tag Manager",
    mode: "analytics",
    note: "Opens the public script endpoint with the normalized analytics tag.",
    buildHint: (context) => context.analyticsTagId || "UA-12345678-1",
    buildUrl: (context) =>
      `https://googletagmanager.com/gtm.js?id=${encodeURIComponent(context.analyticsTagId)}`,
  },
  {
    id: 121,
    title: "BuiltWith Tag Relationships",
    category: "INTEL",
    provider: "BuiltWith",
    mode: "analytics",
    note: "Looks for related sites that reuse the same analytics identifier.",
    buildHint: (context) => context.analyticsCanonical || "UA-12345678",
    buildUrl: (context) =>
      `https://builtwith.com/relationships/tag/${encodeURIComponent(context.analyticsCanonical)}`,
  },
];

const tools = [...domainTools, ...keywordTools, ...analyticsTools];

const interestingLinks = [
  {
    id: "crunchbase",
    title: "Crunchbase Organization",
    provider: "Crunchbase",
    note: "Look for new acquisitions.",
    buildHint: (context) => context.organizationSlug || "example-company",
    buildUrl: (context) =>
      `https://www.crunchbase.com/organization/${encodeURIComponent(context.organizationSlug)}`,
  },
  {
    id: "rapid7-rdns",
    title: "Rapid7 Sonar RDNS",
    provider: "Rapid7",
    note: "Reverse WHOIS and RDNS datasets.",
    buildHint: () => "sonar.rdns_v2",
    buildUrl: () => "https://opendata.rapid7.com/sonar.rdns_v2/",
  },
  {
    id: "hackertarget",
    title: "HackerTarget DNS Search",
    provider: "HackerTarget",
    note: "Enumerate subdomains.",
    buildHint: () => "find-dns-host-records",
    buildUrl: () => "https://hackertarget.com/find-dns-host-records/",
  },
  {
    id: "dnsdumpster",
    title: "DNSDumpster",
    provider: "DNSDumpster",
    note: "Enumerate subdomains.",
    buildHint: () => "dnsdumpster.com",
    buildUrl: () => "https://dnsdumpster.com/",
  },
  {
    id: "securitytrails",
    title: "SecurityTrails",
    provider: "SecurityTrails",
    note: "Enumerate subdomains.",
    buildHint: () => "securitytrails.com",
    buildUrl: () => "https://securitytrails.com/",
  },
  {
    id: "github-search-syntax",
    title: "GitHub Search Syntax",
    provider: "GitHub Gist",
    note: "Reference for finding API keys, secrets, and tokens with GitHub search syntax.",
    buildHint: () => "math-sec / GitHub Search Syntax",
    buildUrl: () => "https://gist.github.com/math-sec/e5f206528807eb962331e33e6eb63dde",
  },
  {
    id: "webapp-wordlists",
    title: "WebApp Wordlists",
    provider: "GitHub",
    note: "Web application wordlists for content discovery and fuzzing.",
    buildHint: () => "math-sec/webapp-wordlists",
    buildUrl: () => "https://github.com/math-sec/webapp-wordlists",
  },
  {
    id: "graphql-wordlist",
    title: "GraphQL Wordlist",
    provider: "GitHub",
    note: "GraphQL-focused wordlist for endpoint and schema testing.",
    buildHint: () => "math-sec/graphql-wordlist",
    buildUrl: () => "https://github.com/math-sec/graphql-wordlist",
  },
  {
    id: "cspbypass",
    title: "CSP Bypass",
    provider: "CSP Bypass",
    note: "Test and research Content Security Policy bypass techniques.",
    buildHint: () => "cspbypass.com",
    buildUrl: () => "https://cspbypass.com/",
  },
  {
    id: "requestbin",
    title: "RequestBin",
    provider: "RequestBin",
    note: "Capture and inspect inbound HTTP requests during testing.",
    buildHint: () => "requestbin.net",
    buildUrl: () => "https://requestbin.net/",
  },
  {
    id: "regex101",
    title: "Regex101",
    provider: "Regex101",
    note: "Test, explain, and debug regular expressions.",
    buildHint: () => "regex101.com",
    buildUrl: () => "https://regex101.com/",
  },
];

const tips = [
  {
    section: "Discovery",
    id: "trademark-tip",
    title: "Trademark Footers",
    body: (context) => {
      const label = context.nameTarget || "Company";
      const slug = slugify(context.nameTarget || "brand");
      return `Look for footer trademark strings like "${label} © 2016", "${label} © 2015", and "${label} © 2017", then pair them with searches like inurl:${slug}.`;
    },
  },
  {
    section: "Discovery",
    id: "analyticsrelationships-tip",
    title: "Analytics Relationships",
    body: () => "Get related domains and subdomains by looking at Google Analytics IDs from URLs.",
    code: "cat subdomains.txt | analyticsrelationships",
    links: [
      {
        label: "AnalyticsRelationships",
        url: "https://github.com/Josue87/AnalyticsRelationships",
      },
    ],
  },
  {
    section: "Discovery",
    id: "rapid7-tip",
    title: "Rapid7 RDNS Workflow",
    body: () => "Use Rapid7 Sonar datasets with shell filters to pivot on domains at scale.",
    code: [
      "aptitude install jq pigz",
      "wget https://opendata.rapid7.com/sonar.fdns_v2/2019-11-29-1574985929-fdns_a.json.gz",
      'cat 2019-11-29-1574985929-fdns_a.json.gz | pigz -dc | grep ".target.org" | jq',
    ].join("\n"),
    links: [
      {
        label: "dnsgrep",
        url: "https://github.com/erbbysam/dnsgrep",
      },
    ],
  },
  {
    section: "Scanning",
    id: "ffuf-tip",
    title: "Avoiding False Negatives in ffuf",
    body: () =>
      "ffuf only considers a limited set of status codes by default, which can hide valid findings when the target responds with less common 2xx or edge-case codes.",
    points: [
      "Default ffuf matches are 200, 204, 301, 302, 307, 401, 403, 405, and 500.",
      "Useful responses like 201 Created, 202 Accepted, 203 Non-Authoritative Information, and 206 Partial Content can be missed.",
      "Use -mc all to capture every code, then filter obvious noise with -fc 404.",
      "If the target rewrites aggressively, also consider filtering 403 or 302 to reduce false positives.",
    ],
    code: "ffuf -mc all -fc 404",
  },
  {
    section: "Scanning",
    id: "recollapse-tip",
    title: "Recollapse",
    body: () => "Generate a large set of breaking strings to stress parsers, filters, and normalization logic on the target.",
    links: [
      {
        label: "recollapse",
        url: "https://github.com/0xacb/recollapse",
      },
    ],
  },
  {
    section: "Scanning",
    id: "changeme-tip",
    title: "changeme",
    body: () => "Create a file with all login panels of web servers and run changeme against that list.",
    links: [
      {
        label: "changeme",
        url: "https://github.com/ztgrace/changeme",
      },
    ],
  },
  {
    section: "Cloud",
    id: "aws-cloud-tip",
    title: "Amazon AWS",
    body: () =>
      "Combine Cognito review, AWS IP and certificate recon, bucket validation, and naming enumeration when mapping AWS exposure.",
    points: [
      "AWS Cognito can expose temporary tokens when identity pools are enabled and weakly configured.",
      "If secrets are found, try them in the AWS CLI and then review privilege-escalation paths.",
      "By visiting IPs under AWS control and checking certificates, it is often possible to find content owned by a company.",
      "Bucket Decloaker can help verify hidden or semi-discoverable bucket exposure.",
      "Use cloud_enum for broader asset discovery.",
    ],
    links: [
      {
        label: "Weak Cognito Configurations",
        url: "https://blog.appsecco.com/exploiting-weak-configurations-in-amazon-cognito-in-aws-471ce761963",
      },
      {
        label: "AWS Misconfigurations",
        url: "https://dhiyaneshgeek.github.io/cloud/security/2022/06/23/aws-misconfigurations/",
      },
      {
        label: "Bucket Decloaker",
        url: "https://gist.github.com/fransr/a155e5bd7ab11c93923ec8ce788e3368",
      },
      {
        label: "awsScrape",
        url: "https://github.com/jhaddix/awsScrape/",
      },
      {
        label: "cloud_enum",
        url: "https://github.com/initstring/cloud_enum",
      },
    ],
  },
  {
    section: "Cloud",
    id: "azure-cloud-tip",
    title: "Azure",
    body: () =>
      "Azure recon should combine takeover checks, tenant and Active Directory metadata review, and tenant-aware spray recon.",
    points: [
      "Check for Azure Edge and CDN takeover opportunities on dangling or misconfigured assets.",
      "Review whether service principals and tenants expose useful metadata.",
      "Some Azure AD tenants are configured as multi-tenant, which may allow external logins into private tenants.",
      "Map Microsoft-owned domains and Azure service patterns used by the target.",
      "Use TREVORspray for recon against assets using Azure tenants.",
      "Use cloud_enum for broader asset discovery.",
    ],
    code: [
      "az ad sp show --id <client_id>",
      "",
      "trevorspray --recon evilcorp.com",
    ].join("\n"),
    links: [
      {
        label: "Azure Edge Takeover",
        url: "https://onetrick.io/2019/09/28/subdomain-takeover-for-azure-cdn/",
      },
      {
        label: "Azure Domains",
        url: "https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-domains",
      },
      {
        label: "TREVORspray",
        url: "https://github.com/blacklanternsecurity/TREVORspray",
      },
      {
        label: "cloud_enum",
        url: "https://github.com/initstring/cloud_enum",
      },
    ],
  },
  {
    section: "Cloud",
    id: "gcp-cloud-tip",
    title: "Google GCP",
    body: () =>
      "Review Google Identity, exposed Firebase behavior, and bucket access patterns together, because GCP exposure often spans auth APIs, storage, and app backends.",
    points: [
      "Applications using Google Identity or Firebase auth may expose admin-sensitive flows.",
      "Endpoints like deleteAccount and signUp can be high-value findings.",
      "Enumerate project and relying party behavior with the exposed API key.",
      "Check what permissions buckets expose before assuming they are private.",
      "If the site ends in appspot.com, the bucket may also be accessible through storage.googleapis.com.",
      "Appending .json to a firebaseio URL may expose the backing database.",
      "Use cloud_enum for broader asset discovery.",
    ],
    code: [
      "POST /identitytoolkit/v3/relyingparty/signupNewUser?key=GOOGLEKEY HTTP/2",
      "Host: www.googleapis.com",
      "X-Client-Version: Firefox/JsCore/8.10.1/FirebaseCore-web",
      "X-Firebase-Locale: pt",
      "Content-Type: application/json",
      "",
      "{\"returnSecureToken\":true,\"email\":\"asassa@asas.com\",\"password\":\"asassa@asas.com\"}",
      "",
      "GET /v1/projects?key=GOOGLEKEY HTTP/2",
      "Host: identitytoolkit.googleapis.com",
      "Content-Type: application/json",
      "X-Client-Version: Chrome/JsCore/9.13.0/FirebaseCore-web",
      "X-Firebase-Locale: en",
      "",
      "https://storage.googleapis.com/<site_url>",
    ].join("\n"),
    links: [
      {
        label: "IdentityToolkit Docs",
        url: "https://developers.google.com/resources/api-libraries/documentation/identitytoolkit/v3/python/latest/identitytoolkit_v3.relyingparty.html",
      },
      {
        label: "Google Identity Misconfigs",
        url: "https://blog.appsecco.com/exploiting-weak-configurations-in-google-identity-platform-cbddbd0e71e3",
      },
      {
        label: "GCPBucketBrute",
        url: "https://github.com/RhinoSecurityLabs/GCPBucketBrute",
      },
      {
        label: "Hunting GCP Buckets",
        url: "https://hackingthe.cloud/gcp/general-knowledge/gcp-buckets/",
      },
      {
        label: "Pyrebase",
        url: "https://github.com/thisbejim/Pyrebase",
      },
      {
        label: "Firebase Notes",
        url: "https://gist.github.com/Anon-Exploiter/5232869d84d01d0e90377410ef25f576",
      },
      {
        label: "cloud_enum",
        url: "https://github.com/initstring/cloud_enum",
      },
    ],
  },
  {
    section: "Bypasses",
    id: "dns-history-bypass-tip",
    title: "DNS History Firewall Bypass",
    body: () => "Use historical DNS data to find alternative paths that may bypass firewalls or filtering layers.",
    links: [
      {
        label: "bypass-firewalls-by-DNS-history",
        url: "https://github.com/vincentcox/bypass-firewalls-by-DNS-history",
      },
    ],
  },
  {
    section: "Bypasses",
    id: "twofa-bypass-tip",
    title: "2FA Bypasses",
    body: () => "Review the full 2FA flow, not only the code entry page, because several bypasses happen in surrounding state transitions and recovery flows.",
    points: [
      "Response manipulation: intercept responses and change values such as 200 or false/true flags.",
      "2FA code reusability.",
      "2FA code leakage in the response.",
      "Password reset flow disables 2FA.",
      "CSRF on 2FA disabling.",
      "Lack of brute-force protection.",
      "Clickjacking on the 2FA disabling page.",
      "Enabling 2FA does not expire previously active sessions.",
      "Bypass 2FA with null or 000000.",
      "Direct access to a page to jump the 2FA process.",
      "2FA code based on timestamp.",
    ],
  },
  {
    section: "Misc",
    id: "vps-burp-tip",
    title: "Send Traffic from VPS to Local Burp",
    body: () =>
      "Forward traffic from a VPS back into your local Burp listener. In WSL environments, make sure port forwarding is also configured on the Windows side.",
    points: [
      "Run the SSH remote forward from the system that can reach the VPS.",
      "If SSH with keys is available, prefer the native ssh command.",
      "If you are on Windows and need password auth, PuTTY can do the same remote forward.",
      "After the tunnel is up, send traffic from the VPS through the forwarded local Burp proxy.",
    ],
    code: [
      "# Run this in terminal connecting to vps (if ssh with key is possible)",
      "# When in WSL, portforwarding needs to be set",
      "ssh -R 8080:127.0.0.1:8080 root@VPS_IP -f -N",
      "",
      "# If you are in windows and need to pass passsord, use this",
      "putty.exe -ssh user@host -pw password -R 8080:127.0.0.1:8080",
      "",
      "# Visit the sites in VPS",
      "curl URL -x http://127.0.0.1:8080",
    ].join("\n"),
  },
  {
    section: "Burp Suite",
    id: "burp-plugins-tip",
    title: "Burp Suite Plugins",
    body: () => "A quick plugin stack for recon, content discovery, JavaScript analysis, authorization checks, and upload testing inside Burp Suite.",
    points: [
      "Backslash Powered Scanner",
      "JS Miner",
      "Active Scan++",
      "JS Link Finder",
      "Param Miner",
      "Reflector",
      "JsLuice+",
      "Sensitive Discoverer",
      "Autorize",
      "Upload Scanner",
      "Collaborator Everywhere",
      "Content Type Converter",
      "Magic Byte Selector",
      "Detect Dynamic JS",
    ],
    links: [
      {
        label: "JsLuice+",
        url: "https://github.com/0x999-x/jsluicepp",
      },
    ],
  },
];

const tipSections = [
  { id: "ALL", label: "All Tips" },
  ...Array.from(new Set(tips.map((tip) => tip.section || "General"))).map((section) => ({
    id: section,
    label: section,
  })),
];

const state = {
  activeCategory: "ALL",
  activeTipSection: "ALL",
  activeView: "modules",
  search: "",
  target: "",
  analytics: "",
  analyticsOpen: false,
};

const elements = {
  analyticsInput: document.querySelector("#analytics-input"),
  analyticsPanel: document.querySelector("#analytics-panel"),
  analyticsSummary: document.querySelector("#analytics-summary"),
  targetInput: document.querySelector("#target-input"),
  targetSummary: document.querySelector("#target-summary"),
  statusRow: document.querySelector(".status-row"),
  toolSearch: document.querySelector("#tool-search"),
  toolGrid: document.querySelector("#tool-grid"),
  workspaceTabs: document.querySelector("#workspace-tabs"),
  viewPanels: [...document.querySelectorAll("[data-view-panel]")],
  interestingLinks: document.querySelector("#interesting-links"),
  tipsFilters: document.querySelector("#tips-filters"),
  tipsGrid: document.querySelector("#tips-grid"),
  categoryFilters: document.querySelector("#category-filters"),
  toolCount: document.querySelector("#tool-count"),
  openVisible: document.querySelector("#open-visible"),
  clearTarget: document.querySelector("#clear-target"),
  targetForm: document.querySelector("#target-form"),
  toast: document.querySelector("#toast"),
};

let toastTimer = null;

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function showToast(message) {
  if (!elements.toast) {
    return;
  }

  elements.toast.textContent = message;
  elements.toast.classList.add("is-visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    elements.toast.classList.remove("is-visible");
  }, 2400);
}

function getToolPool() {
  return tools.filter((tool) =>
    state.analyticsOpen ? tool.mode === "analytics" : tool.mode !== "analytics"
  );
}

function getVisibleTools(context) {
  const query = state.search.toLowerCase();

  return getToolPool().filter((tool) => {
    const matchesCategory = state.analyticsOpen
      ? true
      : state.activeCategory === "ALL" || tool.category === state.activeCategory;

    const searchable = [tool.title, tool.provider, tool.note, categories[tool.category]]
      .join(" ")
      .toLowerCase();

    const matchesSearch = !query || searchable.includes(query);

    return matchesCategory && matchesSearch;
  });
}

function isToolEnabled(tool, context) {
  if (tool.mode === "domain") {
    return context.hasDomain;
  }

  if (tool.mode === "analytics") {
    return context.hasAnalyticsTag;
  }

  return context.hasKeyword;
}

function buildSummary(context) {
  if (!context.raw) {
    return "";
  }

  if (context.hasDomain) {
    return `Target locked to <code>${escapeHtml(context.domainTarget)}</code>.`;
  }

  return `Keyword mode active for <code>${escapeHtml(
    context.raw
  )}</code>.`;
}

function openExternalUrl(url) {
  const popup = window.open("", "_blank");

  if (!popup) {
    return false;
  }

  try {
    popup.opener = null;
  } catch (error) {
    // Ignore browsers that do not allow overriding opener.
  }

  popup.location.replace(url);
  return true;
}

function renderFilters() {
  const counts = tools
    .filter((tool) => tool.mode !== "analytics")
    .reduce(
    (accumulator, tool) => {
      accumulator.ALL += 1;
      accumulator[tool.category] += 1;
      return accumulator;
    },
    {
      ALL: 0,
      DORKS: 0,
      RECON: 0,
      ARCHIVES: 0,
      INTEL: 0,
      FILES: 0,
    }
  );

  elements.categoryFilters.innerHTML = [
    ...Object.entries(categories)
      .map(([category, label]) => {
        const activeClass =
          !state.analyticsOpen && state.activeCategory === category ? "is-active" : "";

        return `
          <button class="filter ${activeClass}" type="button" data-category="${category}">
            <span>${label}</span>
            <strong>${counts[category]}</strong>
          </button>
        `;
      }),
    `
      <button
        class="filter filter-signal ${state.analyticsOpen ? "is-active" : ""}"
        type="button"
        data-filter-action="analytics-toggle"
        aria-pressed="${state.analyticsOpen ? "true" : "false"}"
      >
        <span>Google Tags</span>
        <strong>${analyticsTools.length}</strong>
      </button>
    `,
  ]
    .join("")
    .trim();

  const analyticsToggle = elements.categoryFilters.querySelector(
    '[data-filter-action="analytics-toggle"]'
  );

  analyticsToggle?.addEventListener("click", () => {
    state.analyticsOpen = !state.analyticsOpen;

    persistState();
    render();

    if (state.analyticsOpen) {
      elements.analyticsInput.focus();
    }
  });

  elements.categoryFilters.querySelectorAll("[data-category]").forEach((button) => {
    button.addEventListener("click", () => {
      state.analyticsOpen = false;
      state.activeCategory = button.dataset.category;
      persistState();
      render();
    });
  });
}

function renderWorkspaceTabs() {
  elements.workspaceTabs.querySelectorAll("[data-view]").forEach((button) => {
    const isActive = button.dataset.view === state.activeView;
    button.classList.toggle("is-active", isActive);
    button.setAttribute("aria-selected", String(isActive));
  });

  elements.viewPanels.forEach((panel) => {
    panel.hidden = panel.dataset.viewPanel !== state.activeView;
  });
}

function renderToolCard(tool, context) {
  const enabled = isToolEnabled(tool, context);
  const hint = tool.buildHint(context);
  const preview = enabled
    ? tool.buildUrl(context)
    : tool.mode === "domain"
      ? "Enter a valid domain to enable this module."
      : tool.mode === "analytics"
        ? "Enter a valid Google tag ID to enable this module."
      : "Enter a target to enable this module.";

  return `
    <article class="tool-card ${enabled ? "" : "is-disabled"}" data-category="${tool.category}">
      <div class="tool-top">
        <div class="category-code">${categoryCodes[tool.category]}</div>
        <div>
          <p class="tool-provider">${escapeHtml(tool.provider)}</p>
          <h2 class="tool-title">${escapeHtml(tool.title)}</h2>
        </div>
        <span class="tool-mode">${escapeHtml(modeLabels[tool.mode] || tool.mode)}</span>
      </div>

      <p class="tool-note">${escapeHtml(tool.note)}</p>
      <p class="tool-preview">${escapeHtml(hint)}</p>
      <p class="tool-preview">${escapeHtml(preview)}</p>

      <div class="tool-actions">
        <button class="card-button card-button-primary" type="button" data-action="open" data-id="${tool.id}" ${
          enabled ? "" : "disabled"
        }>
          Launch
        </button>
        <button class="card-button card-button-secondary" type="button" data-action="copy" data-id="${tool.id}" ${
          enabled ? "" : "disabled"
        }>
          Copy URL
        </button>
      </div>
    </article>
  `;
}

function buildAnalyticsSummary(context) {
  if (!context.hasAnalyticsInput) {
    return {
      message: "Accepts UA12345678 or UA-12345678-1. Tag IDs like GTM, G, AW, DC, and GT must keep the hyphen, such as GTM-564S72.",
      invalid: false,
    };
  }

  if (!context.hasAnalyticsTag) {
    return {
      message: "Invalid tag ID. UA may be compact or hyphenated, but tag IDs like GTM-123S45 must keep the hyphen.",
      invalid: true,
    };
  }

  return {
    message: `Normalized to <code>${escapeHtml(
      context.analyticsCanonical
    )}</code> with pivot token <code>${escapeHtml(context.analyticsCompact)}</code>.`,
    invalid: false,
  };
}

function renderAnalyticsPanel(context) {
  const isOpen = state.analyticsOpen;
  const summary = buildAnalyticsSummary(context);

  elements.analyticsPanel.hidden = !isOpen;
  elements.analyticsInput.value = state.analytics;
  elements.analyticsSummary.innerHTML = summary.message;
  elements.analyticsSummary.classList.toggle("is-invalid", summary.invalid);
}

function renderTipsFilters() {
  const counts = tips.reduce(
    (accumulator, tip) => {
      const section = tip.section || "General";
      accumulator.ALL += 1;
      accumulator[section] = (accumulator[section] || 0) + 1;
      return accumulator;
    },
    { ALL: 0 }
  );

  elements.tipsFilters.innerHTML = tipSections
    .map((section) => {
      const activeClass = state.activeTipSection === section.id ? "is-active" : "";

      return `
        <button class="filter ${activeClass}" type="button" data-tip-section="${escapeHtml(section.id)}">
          <span>${escapeHtml(section.label)}</span>
          <strong>${counts[section.id] || 0}</strong>
        </button>
      `;
    })
    .join("");

  elements.tipsFilters.querySelectorAll("[data-tip-section]").forEach((button) => {
    button.addEventListener("click", () => {
      state.activeTipSection = button.dataset.tipSection;
      persistState();
      render();
    });
  });
}

function renderTools() {
  const context = buildContext();
  const visibleTools = getVisibleTools(context);

  if (!visibleTools.length) {
    elements.toolGrid.innerHTML = `
      <div class="empty-state">
        <h2>No modules found</h2>
        <p>Adjust the category filter or search text to bring the modules back.</p>
      </div>
    `;
    elements.toolCount.textContent = "0 visible modules";
    elements.openVisible.disabled = true;
    return;
  }

  elements.toolGrid.innerHTML = visibleTools.map((tool) => renderToolCard(tool, context)).join("");

  const enabledTools = visibleTools.filter((tool) => isToolEnabled(tool, context));
  elements.toolCount.textContent = `${enabledTools.length} of ${visibleTools.length} visible modules are ready to launch.`;
  elements.openVisible.disabled = enabledTools.length === 0;

  elements.toolGrid.querySelectorAll("[data-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      const tool = tools.find((entry) => String(entry.id) === button.dataset.id);

      if (!tool) {
        return;
      }

      if (button.dataset.action === "open") {
        const opened = openExternalUrl(tool.buildUrl(context));

        if (!opened) {
          showToast("The browser blocked this new tab.");
        }

        return;
      }

      try {
        await navigator.clipboard.writeText(tool.buildUrl(context));
        showToast(`URL copied: ${tool.title}`);
      } catch (error) {
        showToast("Could not copy the URL.");
      }
    });
  });
}

function renderInterestingLinks(context) {
  elements.interestingLinks.innerHTML = interestingLinks
    .map((link) => {
      const url = link.buildUrl(context);
      const hint = link.buildHint(context);

      return `
        <article class="resource-card">
          <p class="resource-provider">${escapeHtml(link.provider)}</p>
          <h3 class="resource-title">${escapeHtml(link.title)}</h3>
          <p class="resource-note">${escapeHtml(link.note)}</p>
          <p class="resource-preview">${escapeHtml(hint)}</p>
          <a
            class="card-button card-button-secondary resource-link"
            href="${escapeHtml(url)}"
            target="_blank"
            rel="noopener noreferrer"
          >
            Open Link
          </a>
        </article>
      `;
    })
    .join("");
}

function renderTips(context) {
  const filteredTips = tips.filter((tip) =>
    state.activeTipSection === "ALL" ? true : (tip.section || "General") === state.activeTipSection
  );

  const groupedTips = filteredTips.reduce((accumulator, tip) => {
    const section = tip.section || "General";

    if (!accumulator[section]) {
      accumulator[section] = [];
    }

    accumulator[section].push(tip);
    return accumulator;
  }, {});

  elements.tipsGrid.innerHTML = Object.entries(groupedTips)
    .map(([section, sectionTips]) => {
      const cards = sectionTips
        .map((tip) => {
          const body = tip.body(context);
          const code = tip.code
            ? `<pre class="tip-code"><code>${escapeHtml(tip.code)}</code></pre>`
            : "";
          const points = Array.isArray(tip.points) && tip.points.length
            ? `
              <ul class="tip-points">
                ${tip.points.map((point) => `<li>${escapeHtml(point)}</li>`).join("")}
              </ul>
            `
            : "";
          const links = (tip.links || [])
            .map(
              (link) => `
                <a
                  class="tip-link"
                  href="${escapeHtml(link.url)}"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  ${escapeHtml(link.label)}
                </a>
              `
            )
            .join("");

          return `
            <article class="tip-card">
              <h3 class="resource-title">${escapeHtml(tip.title)}</h3>
              <p class="resource-note">${escapeHtml(body)}</p>
              ${points}
              ${code}
              <div class="tip-links">${links}</div>
            </article>
          `;
        })
        .join("");

      return `
        <section class="tip-section">
          <div class="tip-section-head">
            <p class="section-kicker">Tip Section</p>
            <h3>${escapeHtml(section)}</h3>
          </div>
          <div class="tip-card-grid">
            ${cards}
          </div>
        </section>
      `;
    })
    .join("");
}

function persistState() {
  const snapshot = {
    activeCategory: state.activeCategory,
    activeTipSection: state.activeTipSection,
    activeView: state.activeView,
    analytics: state.analytics,
    analyticsOpen: state.analyticsOpen,
    search: state.search,
    target: state.target,
  };

  window.localStorage.setItem(storageKey, JSON.stringify(snapshot));
}

function restoreState() {
  try {
    const snapshot = JSON.parse(window.localStorage.getItem(storageKey) || "{}");
    state.activeCategory = snapshot.activeCategory || "ALL";
    state.activeTipSection = snapshot.activeTipSection || "ALL";
    state.activeView = snapshot.activeView || "modules";
    state.analytics = snapshot.analytics || "";
    state.analyticsOpen =
      typeof snapshot.analyticsOpen === "boolean"
        ? snapshot.analyticsOpen
        : Boolean(snapshot.analytics);
    state.search = snapshot.search || "";
    state.target = snapshot.target || "";
  } catch (error) {
    state.activeCategory = "ALL";
    state.activeTipSection = "ALL";
    state.activeView = "modules";
    state.analytics = "";
    state.analyticsOpen = false;
    state.search = "";
    state.target = "";
  }
}

function render() {
  const context = buildContext();
  const summary = buildSummary(context);

  elements.analyticsInput.value = state.analytics;
  elements.targetInput.value = state.target;
  elements.toolSearch.value = state.search;
  elements.targetSummary.innerHTML = summary;
  elements.statusRow.classList.toggle("is-empty", !summary);

  renderWorkspaceTabs();
  renderAnalyticsPanel(context);
  renderFilters();
  renderTools();
  renderInterestingLinks(context);
  renderTipsFilters();
  renderTips(context);
}

function handleOpenVisible() {
  const context = buildContext();
  const enabledTools = getVisibleTools(context).filter((tool) => isToolEnabled(tool, context));

  if (!enabledTools.length) {
    showToast("No enabled modules available to launch.");
    return;
  }

  if (
    enabledTools.length > 10 &&
    !window.confirm(`This will try to open ${enabledTools.length} tabs. Continue?`)
  ) {
    return;
  }

  let openedCount = 0;

  enabledTools.forEach((tool) => {
    if (openExternalUrl(tool.buildUrl(context))) {
      openedCount += 1;
    }
  });

  if (openedCount === enabledTools.length) {
    showToast(`Launched ${openedCount} visible modules.`);
    return;
  }

  showToast(
    `Launched ${openedCount} of ${enabledTools.length}. The browser blocked the rest.`
  );
}

function init() {
  restoreState();
  render();

  elements.targetInput.addEventListener("input", (event) => {
    state.target = event.target.value;
    persistState();
    render();
  });

  elements.analyticsInput.addEventListener("input", (event) => {
    state.analytics = event.target.value;
    state.analyticsOpen = true;
    persistState();
    render();
  });

  elements.toolSearch.addEventListener("input", (event) => {
    state.search = event.target.value;
    persistState();
    render();
  });

  elements.workspaceTabs.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => {
      state.activeView = button.dataset.view;
      persistState();
      render();
    });
  });

  elements.clearTarget.addEventListener("click", () => {
    state.analytics = "";
    state.analyticsOpen = false;
    state.target = "";
    persistState();
    render();
    elements.targetInput.focus();
  });

  elements.openVisible.addEventListener("click", handleOpenVisible);
  elements.targetForm.addEventListener("submit", (event) => {
    event.preventDefault();
    handleOpenVisible();
  });
}

init();
