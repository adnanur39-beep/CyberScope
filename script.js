/* =====================================================
   CYBERSCOPE — FINAL APPLICATION SCRIPT
   Features: IP geolocation, validation, history,
   favorites, local storage, CVE reference cards.
===================================================== */

"use strict";

const STORAGE_KEY = "cyberscopeData";
const API_BASE = "https://ipapi.co/";

const $ = (selector, parent = document) => parent.querySelector(selector);

const elements = {
  currentDate: $("#current-date"),
  searchForm: $("#ip-search-form"),
  ipInput: $("#ip-input"),
  searchMessage: $("#search-message"),
  result: $("#ip-result"),
  totalLookups: $("#total-lookups"),
  totalFavorites: $("#total-favorites"),
  totalThreats: $("#total-threats"),
  totalVulnerabilities: $("#total-vulnerabilities"),
  historyBody: $("#history-table-body"),
  historySearch: $("#history-search"),
  clearHistory: $("#clear-history"),
  historyEmpty: $("#history-empty"),
  favoritesList: $("#favorites-list"),
  favoritesEmpty: $("#favorites-empty"),
  favoriteCountLabel: $("#favorite-count-label"),
  cveList: $("#cve-list"),
  mobileMenu: $("#mobile-menu"),
  sidebar: $("#sidebar")
};

const cveData = [
  {
    id: "CVE-2021-44228",
    title: "Apache Log4j2 Remote Code Execution",
    severity: "Critical",
    score: "10.0",
    description: "A critical remote code execution vulnerability affecting Apache Log4j2."
  },
  {
    id: "CVE-2023-34362",
    title: "MOVEit Transfer SQL Injection",
    severity: "Critical",
    score: "9.8",
    description: "A SQL injection vulnerability in MOVEit Transfer that may lead to unauthorized access."
  },
  {
    id: "CVE-2021-26855",
    title: "Microsoft Exchange Server SSRF",
    severity: "High",
    score: "9.1",
    description: "A server-side request forgery vulnerability affecting Microsoft Exchange Server."
  }
];

function loadSavedData() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { searchHistory: [], favorites: [], totalLookups: 0 };

    const parsed = JSON.parse(raw);
    return {
      searchHistory: Array.isArray(parsed.searchHistory) ? parsed.searchHistory : [],
      favorites: Array.isArray(parsed.favorites) ? parsed.favorites : [],
      totalLookups: Number.isFinite(parsed.totalLookups) && parsed.totalLookups >= 0
        ? parsed.totalLookups : 0
    };
  } catch (error) {
    console.warn("CyberScope could not read saved browser data:", error);
    return { searchHistory: [], favorites: [], totalLookups: 0 };
  }
}

const initialData = loadSavedData();
let searchHistory = initialData.searchHistory;
let favorites = initialData.favorites;
let totalLookups = initialData.totalLookups;
let nextHistoryId = searchHistory.reduce(
  (max, item) => Math.max(max, Number(item.id) || 0), 0
) + 1;

function saveAppData() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      searchHistory,
      favorites,
      totalLookups
    }));
    return true;
  } catch (error) {
    console.error("CyberScope could not save browser data:", error);
    showMessage("Browser storage is unavailable or full. Your latest changes may not persist.", "error");
    return false;
  }
}

function showMessage(message, type = "info") {
  if (!elements.searchMessage) return;
  elements.searchMessage.textContent = message;
  elements.searchMessage.className = "search-message";
  if (type === "error") elements.searchMessage.classList.add("error");
  if (type === "success") elements.searchMessage.classList.add("success");
}

function displayDate() {
  if (!elements.currentDate) return;
  elements.currentDate.textContent = new Date().toLocaleDateString("en-US", {
    weekday: "short", year: "numeric", month: "short", day: "numeric"
  });
}

function updateStatistics() {
  if (elements.totalLookups) elements.totalLookups.textContent = totalLookups;
  if (elements.totalFavorites) elements.totalFavorites.textContent = favorites.length;
  if (elements.totalThreats) elements.totalThreats.textContent = "—";
  if (elements.totalVulnerabilities) elements.totalVulnerabilities.textContent = cveData.length;
  if (elements.favoriteCountLabel) {
    elements.favoriteCountLabel.textContent = `${favorites.length} SAVED`;
  }
}

function isValidIPv4(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;

  return parts.every(part => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith("0")) return false;
    const value = Number(part);
    return value >= 0 && value <= 255;
  });
}

function setLoading(loading) {
  const button = elements.searchForm?.querySelector('button[type="submit"]');
  if (button) {
    button.disabled = loading;
    button.innerHTML = loading ? "Looking up..." : 'Analyze IP <span>→</span>';
  }
  if (elements.ipInput) elements.ipInput.disabled = loading;
}

async function fetchIPInformation(ip) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);

  try {
    const response = await fetch(`${API_BASE}${encodeURIComponent(ip)}/json/`, {
      signal: controller.signal,
      headers: { "Accept": "application/json" }
    });

    if (response.status === 429) {
      throw new Error("The geolocation API request limit has been reached. Try again later.");
    }
    if (!response.ok) {
      throw new Error(`The geolocation service returned an error (${response.status}).`);
    }

    const data = await response.json();
    if (data.error || !data.ip) {
      throw new Error(data.reason || "No geolocation information was returned for this IP.");
    }

    return {
      ip: data.ip,
      country: data.country_name || data.country || "Unavailable",
      city: data.city || "Unavailable",
      region: data.region || "Unavailable",
      organization: data.org || "Unavailable",
      asn: data.asn || "Unavailable",
      searchedAt: new Date().toLocaleString(),
      source: "ipapi.co"
    };
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("The request timed out. Please try again.");
    }
    if (error instanceof TypeError) {
      throw new Error("Network or CORS error. Check your internet connection and try again.");
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function makeInfoItem(label, value) {
  const item = document.createElement("div");
  item.className = "result-item";
  const title = document.createElement("span");
  title.className = "result-label";
  title.textContent = label;
  const content = document.createElement("strong");
  content.className = "result-value";
  content.textContent = value || "Unavailable";
  item.append(title, content);
  return item;
}

function displayIPResult(record) {
  if (!elements.result) return;
  elements.result.replaceChildren();

  const card = document.createElement("article");
  card.className = "result-card";

  const header = document.createElement("div");
  header.className = "result-header";
  const heading = document.createElement("h3");
  heading.textContent = "IP Intelligence Result";
  const badge = document.createElement("span");
  badge.className = "demo-badge";
  badge.textContent = "LIVE GEOLOCATION";
  header.append(heading, badge);

  const ipHeading = document.createElement("h2");
  ipHeading.className = "result-ip";
  ipHeading.textContent = record.ip;

  const grid = document.createElement("div");
  grid.className = "result-grid";
  grid.append(
    makeInfoItem("Country", record.country),
    makeInfoItem("City", record.city),
    makeInfoItem("Region", record.region),
    makeInfoItem("Network organization", record.organization),
    makeInfoItem("ASN", record.asn),
    makeInfoItem("Data source", record.source || "Saved browser record")
  );

  const saveButton = document.createElement("button");
  saveButton.type = "button";
  saveButton.className = "favorite-button";
  saveButton.dataset.action = "toggle-favorite";
  saveButton.dataset.ip = record.ip;
  updateFavoriteButton(saveButton, record.ip);

  card.append(header, ipHeading, grid, saveButton);
  elements.result.append(card);
}

function updateFavoriteButton(button, ip) {
  const saved = favorites.some(item => item.ip === ip);
  button.textContent = saved ? "★ Remove from Favorites" : "☆ Save to Favorites";
}

function displayHistory() {
  if (!elements.historyBody) return;
  elements.historyBody.replaceChildren();

  const term = elements.historySearch?.value.trim().toLowerCase() || "";
  const filtered = searchHistory.filter(item => {
    const text = `${item.ip || ""} ${item.city || ""} ${item.country || ""}`.toLowerCase();
    return text.includes(term);
  });

  if (elements.historyEmpty) {
    elements.historyEmpty.hidden = filtered.length > 0;
    elements.historyEmpty.textContent = searchHistory.length === 0
      ? "No investigations yet. Search an IP address to get started."
      : "No matching records found.";
  }

  filtered.forEach(item => {
    const row = document.createElement("tr");
    const ipCell = document.createElement("td");
    ipCell.textContent = item.ip;
    const locationCell = document.createElement("td");
    locationCell.textContent = [item.city, item.country].filter(Boolean).join(", ");
    const dateCell = document.createElement("td");
    dateCell.textContent = item.searchedAt || "Previously saved";
    const saveCell = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.action = "toggle-favorite";
    button.dataset.ip = item.ip;
    button.setAttribute("aria-label", `Toggle favorite for ${item.ip}`);
    updateFavoriteButton(button, item.ip);
    button.textContent = favorites.some(f => f.ip === item.ip) ? "★" : "☆";
    saveCell.append(button);
    row.append(ipCell, locationCell, dateCell, saveCell);
    elements.historyBody.append(row);
  });
}

function displayFavorites() {
  if (!elements.favoritesList) return;
  elements.favoritesList.replaceChildren();

  if (elements.favoritesEmpty) {
    elements.favoritesEmpty.hidden = favorites.length > 0;
  }

  favorites.forEach(item => {
    const card = document.createElement("article");
    card.className = "favorite-card";

    const ip = document.createElement("h3");
    ip.textContent = item.ip;

    const location = document.createElement("p");
    location.textContent = [item.city, item.country].filter(Boolean).join(", ") || "Location unavailable";

    const organization = document.createElement("p");
    organization.textContent = item.organization || "Organization unavailable";

    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Remove saved IP";
    remove.dataset.action = "toggle-favorite";
    remove.dataset.ip = item.ip;

    card.append(ip, location, organization, remove);
    elements.favoritesList.append(card);
  });
}

function toggleFavorite(ip) {
  const existing = favorites.some(item => item.ip === ip);

  if (existing) {
    favorites = favorites.filter(item => item.ip !== ip);
    showMessage("IP removed from saved records.", "success");
  } else {
    const record = searchHistory.find(item => item.ip === ip);
    if (!record) return;
    favorites.unshift({ ...record });
    showMessage("IP saved to favorites.", "success");
  }

  saveAppData();
  displayFavorites();
  displayHistory();
  updateStatistics();

  const current = searchHistory.find(item => item.ip === ip);
  if (current && elements.result?.querySelector(`[data-ip="${CSS.escape(ip)}"]`)) {
    displayIPResult(current);
  }
}

function displayVulnerabilities() {
  if (!elements.cveList) return;
  elements.cveList.replaceChildren();

  cveData.forEach(item => {
    const card = document.createElement("article");
    card.className = "cve-card";

    const id = document.createElement("span");
    id.className = "cve-id";
    id.textContent = item.id;

    const title = document.createElement("h3");
    title.textContent = item.title;

    const severity = document.createElement("span");
    severity.className = `severity-badge ${item.severity.toLowerCase()}`;
    severity.textContent = item.severity;

    const score = document.createElement("p");
    score.textContent = `CVSS score: ${item.score}`;

    const description = document.createElement("p");
    description.textContent = item.description;

    card.append(id, title, severity, score, description);
    elements.cveList.append(card);
  });
}

function handleSearch(event) {
  event.preventDefault();
  const ip = elements.ipInput?.value.trim() || "";

  if (!ip) {
    showMessage("Enter an IPv4 address to begin.", "error");
    elements.ipInput?.focus();
    return;
  }
  if (!isValidIPv4(ip)) {
    showMessage("Invalid IPv4 address. Example: 8.8.8.8", "error");
    elements.ipInput?.focus();
    return;
  }

  setLoading(true);
  showMessage("Retrieving public IP information...", "info");

  fetchIPInformation(ip)
    .then(record => {
      record.id = nextHistoryId++;
      searchHistory.unshift(record);
      totalLookups += 1;
      saveAppData();
      displayIPResult(record);
      displayHistory();
      displayFavorites();
      updateStatistics();
      showMessage("IP information retrieved successfully.", "success");
    })
    .catch(error => {
      console.error("IP lookup failed:", error);
      showMessage(error.message || "Something went wrong. Please try again.", "error");
    })
    .finally(() => setLoading(false));
}

function clearHistory() {
  if (searchHistory.length === 0) {
    showMessage("There is no history to clear.", "info");
    return;
  }

  const confirmed = window.confirm("Clear all investigation history? Saved IP favorites will remain.");
  if (!confirmed) return;

  searchHistory = [];
  saveAppData();
  displayHistory();
  updateStatistics();
  if (elements.result) elements.result.replaceChildren();
  showMessage("Investigation history cleared.", "success");
}

function setupMobileNavigation() {
  elements.mobileMenu?.addEventListener("click", () => {
    elements.sidebar?.classList.toggle("open");
  });

  document.addEventListener("click", event => {
    if (!elements.sidebar || !elements.mobileMenu) return;
    const clickedInside = elements.sidebar.contains(event.target);
    const clickedMenu = elements.mobileMenu.contains(event.target);
    if (!clickedInside && !clickedMenu) elements.sidebar.classList.remove("open");
  });
}

function setupNavigation() {
  document.querySelectorAll('.side-nav a[href^="#"]').forEach(link => {
    link.addEventListener("click", event => {
      const target = document.querySelector(link.getAttribute("href"));
      if (!target) return;
      event.preventDefault();
      target.scrollIntoView({ behavior: "smooth", block: "start" });
      elements.sidebar?.classList.remove("open");
      document.querySelectorAll(".nav-link").forEach(item => item.classList.remove("active"));
      link.classList.add("active");
    });
  });
}

function initializeCyberScope() {
  displayDate();
  displayHistory();
  displayFavorites();
  displayVulnerabilities();
  updateStatistics();

  elements.searchForm?.addEventListener("submit", handleSearch);
  elements.historySearch?.addEventListener("input", displayHistory);
  elements.clearHistory?.addEventListener("click", clearHistory);

  document.addEventListener("click", event => {
    const button = event.target.closest('[data-action="toggle-favorite"]');
    if (button?.dataset.ip) toggleFavorite(button.dataset.ip);
  });

  setupMobileNavigation();
  setupNavigation();

  console.info("CyberScope initialized. Local history and favorites are enabled.");
}

initializeCyberScope();
