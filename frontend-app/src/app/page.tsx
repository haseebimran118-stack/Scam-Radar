"use client";

import { useEffect, useState } from "react";

import {
  ShieldCheck,
  Search,
  AlertTriangle,
  Globe,
  Activity,
  Database,
  ArrowUpRight,
  LockKeyhole,
  Radar,
  ChevronLeft,
  ChevronRight,
  LayoutDashboard,
  RefreshCw,
} from "lucide-react";

import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
} from "recharts";

const API_URL = "http://127.0.0.1:8000";
const CHART_COLORS = [
  "#22d3ee",
  "#818cf8",
  "#34d399",
  "#f59e0b",
  "#f87171",
  "#c084fc",
];

type PageName = "Dashboard" | "URL Checker" | "Threat Analysis" | "Database";

interface WeeklyActivity {
  date: string;
  name: string;
  threats: number;
}

interface Threat {
  name: string;
  count: number;
}

interface DashboardData {
  total_urls: number;
  confirmed_malicious_urls: number;
  high_risk_threats: number;
  sources_connected: number;
  weekly_activity: WeeklyActivity[];
  top_threats: Threat[];
  database: string;
  status: string;
}

interface DatabaseAnalysis {
  found: boolean;
  source: string | null;
  threat: string | null;
  url_status: string | null;
  tags: string[];
}

interface CheckResult {
  url: string;
  local_analysis: Record<string, unknown>;
  database_analysis: DatabaseAnalysis;
  openphish_analysis: Record<string, unknown>;
}

interface AnalysisData {
  total_urls: number;
  threat_types: Threat[];
  sources: Threat[];
  top_hosts: Threat[];
  top_tlds: Threat[];
  url_statuses: Threat[];
}

interface DatabaseRecord {
  id: number;
  url: string;
  host: string;
  url_status: string | null;
  threat: string | null;
  tags: string[];
  date_added: string | null;
  first_seen: string | null;
  last_seen: string | null;
  source: string | null;
}

interface DatabaseResponse {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  records: DatabaseRecord[];
}

const cardClass =
  "rounded-2xl border border-slate-800 bg-[#111b2d] p-6";

const buttonClass =
  "rounded-xl px-4 py-3 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-50";

function formatName(value: string) {
  return value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatDate(value: string | null) {
  if (!value) return "Not available";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return value;

  return date.toLocaleDateString();
}

export default function Home() {
  const [activePage, setActivePage] = useState<PageName>("Dashboard");

  const [dashboard, setDashboard] =
    useState<DashboardData | null>(null);

  const [analysis, setAnalysis] =
    useState<AnalysisData | null>(null);

  const [databaseData, setDatabaseData] =
    useState<DatabaseResponse | null>(null);

  const [loading, setLoading] = useState(true);
  const [pageLoading, setPageLoading] = useState(false);
  const [apiError, setApiError] = useState("");

  const [url, setUrl] = useState("");
  const [checkResult, setCheckResult] =
    useState<CheckResult | null>(null);

  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState("");

  const [dbSearch, setDbSearch] = useState("");
  const [dbPage, setDbPage] = useState(1);

  async function fetchDashboard() {
    try {
      const response = await fetch(`${API_URL}/dashboard`);

      if (!response.ok) {
        throw new Error("Could not load dashboard data.");
      }

      const data: DashboardData = await response.json();

      setDashboard(data);
      setApiError("");
    } catch {
      setApiError(
        "Backend connection failed. Please check the API server."
      );
    } finally {
      setLoading(false);
    }
  }

  async function fetchAnalysis() {
    setPageLoading(true);

    try {
      const response = await fetch(`${API_URL}/threat-analysis`);

      if (!response.ok) {
        throw new Error("Could not load threat analysis.");
      }

      setAnalysis(await response.json());
    } catch {
      setApiError("Could not load threat analysis. Check the backend.");
    } finally {
      setPageLoading(false);
    }
  }

  async function fetchDatabase(page = dbPage, search = dbSearch) {
    setPageLoading(true);

    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: "20",
        search,
      });

      const response = await fetch(
        `${API_URL}/database?${params.toString()}`
      );

      if (!response.ok) {
        throw new Error("Could not load database records.");
      }

      setDatabaseData(await response.json());
      setApiError("");
    } catch {
      setApiError("Could not load database records. Check the backend.");
    } finally {
      setPageLoading(false);
    }
  }

  useEffect(() => {
    fetchDashboard();
  }, []);

  useEffect(() => {
    if (activePage === "Threat Analysis") {
      fetchAnalysis();
    }

    if (activePage === "Database") {
      fetchDatabase(dbPage, dbSearch);
    }
  }, [activePage, dbPage]);

  async function handleCheckURL() {
    if (!url.trim()) {
      setCheckError("Please enter a URL.");
      return;
    }

    setChecking(true);
    setCheckError("");
    setCheckResult(null);

    try {
      const response = await fetch(`${API_URL}/check`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: url.trim() }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "URL checking failed."
        );
      }

      setCheckResult(data);
    } catch (error) {
      setCheckError(
        error instanceof Error
          ? error.message
          : "Something went wrong."
      );
    } finally {
      setChecking(false);
    }
  }

  const stats = [
    {
      title: "Confirmed Malicious URLs",
      value: dashboard
        ? (dashboard.confirmed_malicious_urls ?? dashboard.total_urls).toLocaleString()
        : loading ? "Loading..." : "--",
      icon: Globe,
    },
    {
      title: "High Risk Threats",
      value: dashboard
        ? dashboard.high_risk_threats.toLocaleString()
        : loading ? "Loading..." : "--",
      icon: AlertTriangle,
    },
    {
      title: "Sources Connected",
      value: dashboard
        ? dashboard.sources_connected.toString()
        : loading ? "Loading..." : "--",
      icon: Database,
    },
    {
      title: "System Status",
      value: dashboard?.status === "healthy"
        ? "Healthy"
        : loading ? "Loading..." : "Unavailable",
      icon: Activity,
    },
  ];

  const menuItems: {
    name: PageName;
    icon: typeof Radar;
  }[] = [
    { name: "Dashboard", icon: Radar },
    { name: "URL Checker", icon: Search },
    { name: "Threat Analysis", icon: AlertTriangle },
    { name: "Database", icon: Database },
  ];

  function navigate(page: PageName) {
    setActivePage(page);
    setApiError("");
  }

  function renderURLChecker() {
    return (
      <div className={cardClass}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-bold">URL Security Checker</h3>
            <p className="mt-2 text-sm text-slate-400">
              Analyze URLs using local checks, database records and OpenPhish.
            </p>
          </div>
          <ArrowUpRight className="text-cyan-400" />
        </div>

        <div className="mt-6 flex flex-wrap items-center gap-3">
          <input
            type="text"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") handleCheckURL();
            }}
            placeholder="Enter URL to analyze..."
            className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-[#080d18] px-4 py-4 text-white outline-none focus:border-cyan-400"
          />

          <button
            onClick={handleCheckURL}
            disabled={checking}
            className={`${buttonClass} bg-cyan-500 text-slate-950 hover:bg-cyan-400`}
          >
            {checking ? "Checking..." : "Check URL"}
          </button>
        </div>

        {checkError && (
          <p className="mt-4 text-sm text-red-400">{checkError}</p>
        )}

        {checkResult && (
          <div className="mt-6 rounded-xl border border-slate-700 bg-[#080d18] p-5">
            <h4 className="mb-3 font-semibold text-cyan-400">
              Analysis Result
            </h4>

            <p className="mb-5 break-all text-sm text-slate-300">
              URL: {checkResult.url}
            </p>

            <div className={`mb-6 rounded-xl border p-4 ${
              checkResult.database_analysis?.found
                ? "border-red-500/30 bg-red-500/10"
                : "border-emerald-500/30 bg-emerald-500/10"
            }`}>
              <div className="flex items-center gap-2">
                <Database size={20} />
                <h4 className="font-semibold">Database Analysis</h4>
              </div>

              <p className={`mt-3 font-semibold ${
                checkResult.database_analysis?.found
                  ? "text-red-400"
                  : "text-emerald-400"
              }`}>
                {checkResult.database_analysis?.found
                  ? "Reported malicious URL found in database"
                  : "URL not found in local database"}
              </p>

              <div className="mt-3 space-y-2 text-sm text-slate-300">
                <p>Source: {checkResult.database_analysis?.source || "Not available"}</p>
                <p>Threat: {checkResult.database_analysis?.threat || "Not available"}</p>
                <p>Status: {checkResult.database_analysis?.url_status || "Not available"}</p>
                <p>Tags: {checkResult.database_analysis?.tags?.join(", ") || "None"}</p>
              </div>
            </div>

            <p className="mb-2 text-sm font-semibold">Local Analysis</p>
            <pre className="mb-5 overflow-x-auto whitespace-pre-wrap break-words rounded-lg bg-slate-900 p-3 text-xs text-slate-300">
              {JSON.stringify(checkResult.local_analysis, null, 2)}
            </pre>

            <p className="mb-2 text-sm font-semibold">OpenPhish Analysis</p>
            <pre className="overflow-x-auto whitespace-pre-wrap break-words rounded-lg bg-slate-900 p-3 text-xs text-slate-300">
              {JSON.stringify(checkResult.openphish_analysis, null, 2)}
            </pre>

            <p className="mt-4 text-xs text-amber-400">
              Automated results are indicators, not a guarantee that a URL is safe.
              Avoid opening suspicious links.
            </p>
          </div>
        )}
      </div>
    );
  }

  function renderDashboard() {
    return (
      <>
        <div className="mb-8 grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
          {stats.map((stat) => {
            const Icon = stat.icon;

            return (
              <div key={stat.title} className={cardClass}>
                <div className="mb-5 flex items-center justify-between">
                  <p className="text-sm text-slate-400">{stat.title}</p>
                  <Icon className="text-cyan-400" size={22} />
                </div>
                <h3 className="text-2xl font-bold">{stat.value}</h3>
                <p className="mt-2 text-xs text-slate-500">
                  Live database information
                </p>
              </div>
            );
          })}
        </div>

        <div className="mb-8 grid gap-6 xl:grid-cols-3">
          <div className={`${cardClass} xl:col-span-2`}>
            <div className="mb-6 flex items-center justify-between">
              <div>
                <h3 className="text-lg font-bold">Threat Activity</h3>
                <p className="text-sm text-slate-400">
                  Report activity over the last seven days
                </p>
              </div>
              <Activity className="text-cyan-400" />
            </div>

            <div className="h-72">
              {dashboard && dashboard.weekly_activity.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={dashboard.weekly_activity}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#263449" />
                    <XAxis dataKey="name" stroke="#94a3b8" />
                    <YAxis stroke="#94a3b8" />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#111b2d",
                        border: "1px solid #334155",
                        borderRadius: "10px",
                      }}
                    />
                    <Bar dataKey="threats" fill="#22d3ee" radius={[6, 6, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full items-center justify-center text-sm text-slate-400">
                  {loading ? "Loading chart..." : "No activity data available."}
                </div>
              )}
            </div>
          </div>

          <div className={cardClass}>
            <h3 className="mb-2 text-lg font-bold">Threat Intelligence</h3>
            <p className="mb-6 text-sm text-slate-400">
              Most common threat types
            </p>

            <div className="space-y-4">
              {dashboard?.top_threats.map((threat) => (
                <div key={threat.name} className="flex items-center justify-between gap-3">
                  <span className="break-all text-sm text-slate-300">
                    {formatName(threat.name)}
                  </span>
                  <span className="shrink-0 rounded-lg bg-cyan-500/10 px-3 py-1 text-sm text-cyan-400">
                    {threat.count.toLocaleString()}
                  </span>
                </div>
              ))}

              <div className="border-t border-slate-700 pt-5">
                <p className="text-sm text-slate-400">Database</p>
                <p className="mt-2 font-semibold">{dashboard?.database || "Loading..."}</p>
              </div>
            </div>
          </div>
        </div>

        {renderURLChecker()}
      </>
    );
  }

  function renderThreatAnalysis() {
    if (pageLoading && !analysis) {
      return <p className="text-slate-400">Loading threat analysis...</p>;
    }

    if (!analysis) {
      return (
        <div className={cardClass}>
          <p className="text-slate-400">Threat analysis data is unavailable.</p>
          <button
            onClick={fetchAnalysis}
            className={`${buttonClass} mt-4 bg-cyan-500 text-slate-950`}
          >
            Retry
          </button>
        </div>
      );
    }

    const sections = [
      { title: "Threat Types", data: analysis.threat_types },
      { title: "Data Sources", data: analysis.sources },
      { title: "Top Hosts", data: analysis.top_hosts },
      { title: "Top TLDs", data: analysis.top_tlds },
      { title: "URL Status", data: analysis.url_statuses },
    ];

    return (
      <div className="space-y-6">
        <div className={cardClass}>
          <p className="text-sm text-slate-400">Total database records analyzed</p>
          <h3 className="mt-2 text-3xl font-bold text-cyan-400">
            {analysis.total_urls.toLocaleString()}
          </h3>
        </div>

        <div className="grid gap-6 xl:grid-cols-2">
          <div className={cardClass}>
            <h3 className="mb-5 text-lg font-bold">Threat Distribution</h3>
            <div className="h-72">
              {analysis.threat_types.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={analysis.threat_types}
                      dataKey="count"
                      nameKey="name"
                      outerRadius={100}
                      label={({ name, percent }) =>
                        `${formatName(String(name))} (${(Number(percent) * 100).toFixed(0)}%)`
                      }
                    >
                      {analysis.threat_types.map((item, index) => (
                        <Cell
                          key={item.name}
                          fill={CHART_COLORS[index % CHART_COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <p className="text-slate-400">No threat data available.</p>
              )}
            </div>
          </div>

          <div className={cardClass}>
            <h3 className="mb-5 text-lg font-bold">Threat Counts</h3>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={analysis.threat_types} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#263449" />
                  <XAxis type="number" stroke="#94a3b8" />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={130}
                    stroke="#94a3b8"
                    tickFormatter={formatName}
                  />
                  <Tooltip />
                  <Bar dataKey="count" fill="#22d3ee" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          {sections.map((section) => (
            <div key={section.title} className={cardClass}>
              <h3 className="mb-5 text-lg font-bold">{section.title}</h3>
              <div className="space-y-4">
                {section.data.length ? section.data.map((item) => (
                  <div key={item.name} className="flex items-center justify-between gap-4 border-b border-slate-800 pb-3">
                    <span className="break-all text-sm text-slate-300">
                      {formatName(item.name)}
                    </span>
                    <span className="shrink-0 rounded-lg bg-cyan-500/10 px-3 py-1 text-sm text-cyan-400">
                      {item.count.toLocaleString()}
                    </span>
                  </div>
                )) : (
                  <p className="text-sm text-slate-400">No data available.</p>
                )}
              </div>
            </div>
          ))}
        </div>

        <button
          onClick={fetchAnalysis}
          className={`${buttonClass} bg-slate-700 text-white hover:bg-slate-600`}
        >
          <RefreshCw className="mr-2 inline" size={16} />
          Refresh Analysis
        </button>
      </div>
    );
  }

  function renderDatabase() {
    return (
      <div className={cardClass}>
        <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-bold">Malicious URL Database</h3>
            <p className="mt-2 text-sm text-slate-400">
              Browse and search actual stored records.
            </p>
          </div>
          <span className="rounded-lg bg-cyan-500/10 px-3 py-2 text-sm text-cyan-400">
            {databaseData?.total.toLocaleString() ?? "..."} Records
          </span>
        </div>

        <form
          className="mb-6 flex flex-wrap gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            setDbPage(1);
            fetchDatabase(1, dbSearch);
          }}
        >
          <input
            value={dbSearch}
            onChange={(event) => setDbSearch(event.target.value)}
            placeholder="Search URL, host or threat..."
            className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-[#080d18] px-4 py-3 text-white outline-none focus:border-cyan-400"
          />
          <button
            type="submit"
            disabled={pageLoading}
            className={`${buttonClass} bg-cyan-500 text-slate-950 hover:bg-cyan-400`}
          >
            <Search className="mr-2 inline" size={16} />
            Search
          </button>
          <button
            type="button"
            onClick={() => {
              setDbSearch("");
              setDbPage(1);
              fetchDatabase(1, "");
            }}
            className={`${buttonClass} bg-slate-700 text-white hover:bg-slate-600`}
          >
            Clear
          </button>
        </form>

        {pageLoading && (
          <p className="mb-4 text-sm text-cyan-400">Loading records...</p>
        )}

        <div className="overflow-x-auto">
          <table className="w-full min-w-[850px] text-left text-sm">
            <thead className="bg-slate-900 text-slate-400">
              <tr>
                <th className="p-3">ID</th>
                <th className="p-3">URL / Host</th>
                <th className="p-3">Threat</th>
                <th className="p-3">Status</th>
                <th className="p-3">Source</th>
                <th className="p-3">Date Added</th>
              </tr>
            </thead>
            <tbody>
              {databaseData?.records.map((record) => (
                <tr key={record.id} className="border-b border-slate-800 hover:bg-slate-900/60">
                  <td className="p-3 text-slate-400">{record.id}</td>
                  <td className="max-w-xs p-3">
                    <p className="break-all text-cyan-300">{record.url}</p>
                    <p className="mt-1 break-all text-xs text-slate-500">{record.host}</p>
                  </td>
                  <td className="p-3 text-slate-300">
                    {formatName(record.threat || "Unknown")}
                  </td>
                  <td className="p-3 text-slate-300">
                    {record.url_status || "Unknown"}
                  </td>
                  <td className="p-3 text-slate-300">
                    {record.source || "Unknown"}
                  </td>
                  <td className="p-3 text-slate-400">
                    {formatDate(record.date_added || record.first_seen)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {!pageLoading && databaseData?.records.length === 0 && (
          <p className="py-10 text-center text-slate-400">
            No matching database records found.
          </p>
        )}

        <div className="mt-6 flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-slate-400">
            Page {databaseData?.page ?? 1} of {databaseData?.total_pages ?? 1}
          </p>

          <div className="flex gap-2">
            <button
              disabled={!databaseData || databaseData.page <= 1 || pageLoading}
              onClick={() => setDbPage((page) => Math.max(1, page - 1))}
              className={`${buttonClass} bg-slate-700 text-white`}
            >
              <ChevronLeft className="inline" size={16} />
              Previous
            </button>

            <button
              disabled={
                !databaseData ||
                databaseData.page >= databaseData.total_pages ||
                pageLoading
              }
              onClick={() => setDbPage((page) => page + 1)}
              className={`${buttonClass} bg-slate-700 text-white`}
            >
              Next
              <ChevronRight className="inline" size={16} />
            </button>
          </div>
        </div>
      </div>
    );
  }

  const pageDescriptions: Record<PageName, string> = {
    Dashboard: "Monitor malicious URLs and phishing threats.",
    "URL Checker": "Check a URL against threat intelligence sources.",
    "Threat Analysis": "Explore threat types, domains, sources and URL patterns.",
    Database: "Browse and search stored malicious URL records.",
  };

  return (
    <main className="min-h-screen bg-[#080d18] text-white">
      <div className="flex min-h-screen">
        <aside className="hidden min-h-screen w-64 shrink-0 border-r border-slate-800 bg-[#0c1423] p-6 md:block">
          <div className="mb-12 flex items-center gap-3">
            <div className="rounded-xl bg-cyan-500/15 p-3">
              <ShieldCheck className="h-7 w-7 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold">Scam Radar</h1>
              <p className="text-xs text-slate-400">Threat Intelligence</p>
            </div>
          </div>

          <p className="mb-4 text-xs font-semibold uppercase tracking-widest text-slate-500">
            Main Menu
          </p>

          <nav className="space-y-3">
            {menuItems.map((item) => {
              const Icon = item.icon;
              const selected = activePage === item.name;

              return (
                <button
                  key={item.name}
                  onClick={() => navigate(item.name)}
                  className={`flex w-full items-center gap-3 rounded-xl px-4 py-3 text-left transition ${
                    selected
                      ? "bg-cyan-500/10 text-cyan-400"
                      : "text-slate-400 hover:bg-slate-800 hover:text-white"
                  }`}
                >
                  <Icon size={19} />
                  {item.name}
                </button>
              );
            })}
          </nav>

          <div className="mt-20 rounded-xl border border-slate-700 bg-slate-900 p-4">
            <LockKeyhole className="mb-3 text-cyan-400" />
            <p className="font-semibold">Security Monitor</p>
            <p className="mt-1 text-xs text-slate-400">
              Monitoring malicious URL patterns.
            </p>
          </div>
        </aside>

        <section className="min-w-0 flex-1 p-6 md:p-10">
          <header className="mb-8 flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-sm text-cyan-400">SECURITY OVERVIEW</p>
              <h2 className="mt-2 text-3xl font-bold">{activePage}</h2>
              <p className="mt-2 text-slate-400">
                {pageDescriptions[activePage]}
              </p>
            </div>

            <div className={`flex items-center gap-2 rounded-full border px-4 py-2 text-sm ${
              dashboard
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                : "border-red-500/30 bg-red-500/10 text-red-400"
            }`}>
              <span className={`h-2 w-2 rounded-full ${
                dashboard ? "bg-emerald-400" : "bg-red-400"
              }`} />
              {dashboard ? "Backend Connected" : "Backend Unavailable"}
            </div>
          </header>

          <div className="mb-6 flex gap-2 overflow-x-auto md:hidden">
            {menuItems.map((item) => (
              <button
                key={item.name}
                onClick={() => navigate(item.name)}
                className={`${buttonClass} whitespace-nowrap ${
                  activePage === item.name
                    ? "bg-cyan-500 text-slate-950"
                    : "bg-slate-800 text-slate-300"
                }`}
              >
                {item.name}
              </button>
            ))}
          </div>

          {apiError && (
            <div className="mb-6 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
              {apiError}
            </div>
          )}

          {activePage === "Dashboard" && renderDashboard()}
          {activePage === "URL Checker" && renderURLChecker()}
          {activePage === "Threat Analysis" && renderThreatAnalysis()}
          {activePage === "Database" && renderDatabase()}

          <footer className="mt-10 text-center text-xs text-slate-500">
            Scam Radar © 2026 — Malicious URL Intelligence Platform
          </footer>
        </section>
      </div>
    </main>
  );
}