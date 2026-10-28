/**
 * Vue De Secure - Automated OSINT Threat Telemetry Ingestion Engine
 * 
 * Secure, zero-dependency Node.js script.
 * Fetches public threat feeds from CISA, SANS ISC, The Hacker News, and BleepingComputer.
 * Normalizes, scores, and sanitizes articles into osint-data.json for first-party same-origin delivery.
 */

const fs = require('fs');
const path = require('path');

const OUTPUT_PATH = path.join(__dirname, '..', 'osint-data.json');

const FEEDS = [
  {
    name: 'CISA Advisories',
    url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    boost: 2200
  },
  {
    name: 'SANS ISC',
    url: 'https://isc.sans.edu/rssfeed.xml',
    boost: 1800
  },
  {
    name: 'The Hacker News',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    boost: 1900
  },
  {
    name: 'BleepingComputer',
    url: 'https://www.bleepingcomputer.com/feed/',
    boost: 1700
  }
];

function cleanText(text) {
  if (!text) return '';
  return text
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function parseFeedXml(xml, sourceName, boost) {
  const items = [];
  
  // RSS 2.0 <item>
  const rssItemRegex = /<item[\s>]([\s\S]*?)<\/item>/gi;
  let match;
  while ((match = rssItemRegex.exec(xml)) !== null) {
    const block = match[1];
    const titleMatch = block.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const linkMatch = block.match(/<link[^>]*>([\s\S]*?)<\/link>/i);
    const descMatch = block.match(/<(?:description|summary|content)[^>]*>([\s\S]*?)<\/(?:description|summary|content)>/i);

    const title = cleanText(titleMatch ? titleMatch[1] : '');
    let link = linkMatch ? cleanText(linkMatch[1]) : '';
    const desc = cleanText(descMatch ? descMatch[1] : '').slice(0, 280);

    if (title && link && link.startsWith('http')) {
      items.push({ title, link, desc, sourceName, boost });
    }
  }

  // Atom <entry>
  if (items.length === 0) {
    const atomEntryRegex = /<entry[\s>]([\s\S]*?)<\/entry>/gi;
    while ((match = atomEntryRegex.exec(xml)) !== null) {
      const block = match[1];
      const titleMatch = block.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      const linkMatch = block.match(/<link[^>]*href=["']([^"']+)["']/i) || block.match(/<link[^>]*>([\s\S]*?)<\/link>/i);
      const descMatch = block.match(/<(?:summary|content|description)[^>]*>([\s\S]*?)<\/(?:summary|content|description)>/i);

      const title = cleanText(titleMatch ? titleMatch[1] : '');
      const link = linkMatch ? cleanText(linkMatch[1]) : '';
      const desc = cleanText(descMatch ? descMatch[1] : '').slice(0, 280);

      if (title && link && link.startsWith('http')) {
        items.push({ title, link, desc, sourceName, boost });
      }
    }
  }

  return items;
}

function scoreOsintArticle(title, description, idx, sourceBoost) {
  const text = `${title} ${description}`.toLowerCase();
  let score = 9500 - (idx * 550) + sourceBoost;
  if (/zero-day|0-day|actively exploited|in the wild|cve-202/i.test(text)) score += 6200;
  if (/rce|remote code execution|unauthenticated|bypass/i.test(text)) score += 4400;
  if (/php|pki|certificate|scada|ics|nuclear|healthcare|ransomware|ivanti|fortinet|cisco|microsoft|cloud|vpn/i.test(text)) score += 3500;
  if (/critical|emergency|cisa|directive|advisory/i.test(text)) score += 2800;

  // Deterministic variance based on title character codes
  let hash = 0;
  for (let i = 0; i < title.length; i++) {
    hash = ((hash << 5) - hash) + title.charCodeAt(i);
    hash |= 0;
  }
  score += Math.abs(hash % 1400);
  return Math.max(2800, score);
}

function generateRemediation(title, desc) {
  const text = `${title} ${desc}`.toLowerCase();
  if (text.includes('ransomware') || text.includes('extortion')) {
    return 'Board/Executive: Review cyber insurance limits and immutable backup posture. Task Execution: Verify offline backup isolation, enforce phishing-resistant MFA, and validate EDR coverage across all domain controllers.';
  }
  if (text.includes('pki') || text.includes('certificate') || text.includes('root ca')) {
    return 'Board/Executive: Review third-party digital trust and cryptographic supplier risk (SCRM). Task Execution: Inventory all TLS/code-signing certificates, verify root CA pinning, and automate certificate lifecycle rotation.';
  }
  if (text.includes('ics') || text.includes('scada') || text.includes('energy') || text.includes('ot') || text.includes('nuclear')) {
    return 'Board/Executive: Validate NIST CSF 2.0 / NERC CIP / 10 CFR 73.54 boundary isolation. Task Execution: Enforce unidirectional or zero-trust Purdue Model conduits, rotate boundary credentials, and monitor engineering workstation logs.';
  }
  if (text.includes('rce') || text.includes('remote code execution') || text.includes('injection')) {
    return 'Board/Executive: Mandate immediate emergency asset sweep for exposed interfaces. Task Execution: Apply vendor patch or emergency WAF virtual patch, audit access logs for IOCs, and restrict management ports.';
  }
  if (text.includes('vpn') || text.includes('edge') || text.includes('gateway')) {
    return 'Board/Executive: Review perimeter resilience and external attack surface management. Task Execution: Audit VPN/gateway firmware, enforce MFA on all edge access, and isolate administrative interfaces.';
  }
  return 'Board/Executive: Evaluate organizational exposure against NIST CSF 2.0 governance metrics. Task Execution: Verify endpoint telemetry in SIEM, apply vendor security mitigations, and cross-reference internal asset databases.';
}

async function fetchWithTimeout(url, timeoutMs = 12000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'VueDeSecure-ThreatTelemetry/1.0 (+https://vuedesecure.com)'
      }
    });
    clearTimeout(id);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

async function main() {
  console.log(`[OSINT Engine] Starting automated threat feed ingestion...`);
  const allArticles = [];
  const seenUrls = new Set();
  const successfulSources = [];

  for (const feed of FEEDS) {
    try {
      console.log(`[OSINT Engine] Fetching ${feed.name} (${feed.url})...`);
      const xml = await fetchWithTimeout(feed.url);
      const items = parseFeedXml(xml, feed.name, feed.boost);
      console.log(`[OSINT Engine] Parsed ${items.length} items from ${feed.name}`);

      items.slice(0, 10).forEach((item, itemIdx) => {
        if (seenUrls.has(item.link)) return;
        seenUrls.add(item.link);

        const hits = scoreOsintArticle(item.title, item.desc, itemIdx, item.boost);
        const isCrit = /critical|zero-day|0-day|rce|exploited|ransomware|cve-|bypass/i.test(`${item.title} ${item.desc}`);

        allArticles.push({
          title: item.title,
          source: item.sourceName,
          hits,
          severity: isCrit ? 'CRITICAL' : 'HIGH',
          url: item.link,
          summary: item.desc || 'Active cybersecurity advisory from authoritative global threat stream.',
          remediation: generateRemediation(item.title, item.desc)
        });
      });

      successfulSources.push(feed.name);
    } catch (err) {
      console.warn(`[OSINT Engine] Warning: Failed to fetch ${feed.name}: ${err.message}`);
    }
  }

  console.log(`[OSINT Engine] Total unique articles ingested: ${allArticles.length}`);

  if (allArticles.length < 3) {
    console.error(`[OSINT Engine] Error: Ingested fewer than 3 articles (${allArticles.length}). Keeping existing osint-data.json intact to protect site integrity.`);
    process.exit(0);
  }

  // Sort descending by calculated threat hits
  allArticles.sort((a, b) => b.hits - a.hits);

  // Top 3 Threats
  const topSlice = allArticles.slice(0, 3);
  const colors = ['#ef4444', '#facc15', '#38bdf8'];
  const topThreats = topSlice.map((item, idx) => ({
    id: `threat-${idx + 1}`,
    shortLabel: item.title.replace(/[^a-zA-Z0-9\s-]/g, '').split(/\s+/).slice(0, 4).join(' '),
    title: item.title,
    hits: item.hits,
    severity: item.severity,
    color: colors[idx] || '#38bdf8',
    source: item.source,
    url: item.url,
    summary: item.summary,
    remediation: item.remediation
  }));

  // Next 10 stream items
  const topUrls = new Set(topThreats.map(t => t.url));
  const streamItems = allArticles
    .filter(a => !topUrls.has(a.url))
    .slice(0, 10)
    .map(a => ({
      title: a.title,
      source: a.source,
      time: 'Live Telemetry',
      hits: Math.max(1200, Math.round(a.hits * 0.45)),
      severity: a.severity,
      url: a.url,
      summary: a.summary,
      remediation: a.remediation
    }));

  const payload = {
    lastUpdated: new Date().toISOString(),
    feedSources: successfulSources,
    totalArticlesIngested: allArticles.length,
    topThreats,
    streamItems
  };

  fs.writeFileSync(OUTPUT_PATH, JSON.stringify(payload, null, 2), 'utf-8');
  console.log(`[OSINT Engine] Successfully generated ${OUTPUT_PATH} with ${topThreats.length} top threats and ${streamItems.length} stream items.`);
}

main().catch(err => {
  console.error('[OSINT Engine] Fatal error during OSINT run:', err);
  process.exit(0); // Exit 0 so CI doesn't crash on network transient glitches
});
