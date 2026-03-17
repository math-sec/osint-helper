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

const tools = [...domainTools, ...keywordTools];

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
];

const tips = [
  {
    id: "trademark-tip",
    title: "Trademark Footers",
    body: (context) => {
      const label = context.nameTarget || "Company";
      const slug = slugify(context.nameTarget || "brand");
      return `Look for footer trademark strings like "${label} © 2016", "${label} © 2015", and "${label} © 2017", then pair them with searches like inurl:${slug}.`;
    },
  },
  {
    id: "rapid7-tip",
    title: "Rapid7 RDNS Workflow",
    body: () => "Use Rapid7 Sonar datasets with shell filters to pivot on domains at scale.",
    code: [
      "aptitude install jq pigz",
      "wget https://opendata.rapid7.com/sonar.fdns_v2/2019-11-29-1574985929-fdns_a.json.gz",
      'cat 2019-11-29-1574985929-fdns_a.json.gz | pigz -dc | grep ".target.org" | jq',
    ].join("\n"),
    linkLabel: "dnsgrep",
    linkUrl: "https://github.com/erbbysam/dnsgrep",
  },
];

const state = {
  activeCategory: "ALL",
  activeView: "modules",
  search: "",
  target: "",
};

const elements = {
  targetInput: document.querySelector("#target-input"),
  targetSummary: document.querySelector("#target-summary"),
  statusRow: document.querySelector(".status-row"),
  toolSearch: document.querySelector("#tool-search"),
  toolGrid: document.querySelector("#tool-grid"),
  workspaceTabs: document.querySelector("#workspace-tabs"),
  viewPanels: [...document.querySelectorAll("[data-view-panel]")],
  interestingLinks: document.querySelector("#interesting-links"),
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

function getVisibleTools() {
  const query = state.search.toLowerCase();

  return tools.filter((tool) => {
    const matchesCategory =
      state.activeCategory === "ALL" || tool.category === state.activeCategory;

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
  const counts = tools.reduce(
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

  elements.categoryFilters.innerHTML = Object.entries(categories)
    .map(([category, label]) => {
      const activeClass = state.activeCategory === category ? "is-active" : "";

      return `
        <button class="filter ${activeClass}" type="button" data-category="${category}">
          <span>${label}</span>
          <strong>${counts[category]}</strong>
        </button>
      `;
    })
    .join("");

  elements.categoryFilters.querySelectorAll("[data-category]").forEach((button) => {
    button.addEventListener("click", () => {
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
      : "Enter a target to enable this module.";

  return `
    <article class="tool-card ${enabled ? "" : "is-disabled"}" data-category="${tool.category}">
      <div class="tool-top">
        <div class="category-code">${categoryCodes[tool.category]}</div>
        <div>
          <p class="tool-provider">${escapeHtml(tool.provider)}</p>
          <h2 class="tool-title">${escapeHtml(tool.title)}</h2>
        </div>
        <span class="tool-mode">${tool.mode === "domain" ? "domain" : "keyword"}</span>
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

function renderTools() {
  const context = buildTargetContext(state.target);
  const visibleTools = getVisibleTools();

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
  elements.tipsGrid.innerHTML = tips
    .map((tip) => {
      const body = tip.body(context);
      const code = tip.code
        ? `<pre class="tip-code"><code>${escapeHtml(tip.code)}</code></pre>`
        : "";
      const link = tip.linkUrl
        ? `
          <a
            class="tip-link"
            href="${escapeHtml(tip.linkUrl)}"
            target="_blank"
            rel="noopener noreferrer"
          >
            ${escapeHtml(tip.linkLabel)}
          </a>
        `
        : "";

      return `
        <article class="tip-card">
          <h3 class="resource-title">${escapeHtml(tip.title)}</h3>
          <p class="resource-note">${escapeHtml(body)}</p>
          ${code}
          ${link}
        </article>
      `;
    })
    .join("");
}

function persistState() {
  const snapshot = {
    activeCategory: state.activeCategory,
    activeView: state.activeView,
    search: state.search,
    target: state.target,
  };

  window.localStorage.setItem(storageKey, JSON.stringify(snapshot));
}

function restoreState() {
  try {
    const snapshot = JSON.parse(window.localStorage.getItem(storageKey) || "{}");
    state.activeCategory = snapshot.activeCategory || "ALL";
    state.activeView = snapshot.activeView || "modules";
    state.search = snapshot.search || "";
    state.target = snapshot.target || "";
  } catch (error) {
    state.activeCategory = "ALL";
    state.activeView = "modules";
    state.search = "";
    state.target = "";
  }
}

function render() {
  const context = buildTargetContext(state.target);
  const summary = buildSummary(context);

  elements.targetInput.value = state.target;
  elements.toolSearch.value = state.search;
  elements.targetSummary.innerHTML = summary;
  elements.statusRow.classList.toggle("is-empty", !summary);

  renderWorkspaceTabs();
  renderFilters();
  renderTools();
  renderInterestingLinks(context);
  renderTips(context);
}

function handleOpenVisible() {
  const context = buildTargetContext(state.target);
  const enabledTools = getVisibleTools().filter((tool) => isToolEnabled(tool, context));

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
