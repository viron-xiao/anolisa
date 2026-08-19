import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ContainmentDialog } from '../components/ContainmentDialog';
import { ContainmentLifecycleCard } from '../components/ContainmentLifecycleCard';
import { Pagination as PaginationNew } from '../components/Pagination';
import {
  fetchSecurityCase,
  fetchSecurityCases,
  fetchAuditEvents,
  fetchAuditSessions,
  fetchAuditSummary,
  fetchEnforcementBindings,
  reviewSecurityCase,
  type EnforcementBinding,
  type SecurityEventRecord,
  type SecurityEvidenceEvent,
  type SecurityRiskCase,
  type SecurityRiskCaseDetail,
  type SecurityReviewStatus,
  type SecuritySessionSummary,
  type SecuritySummary,
} from '../utils/apiClient';

type AuditTab = 'overview' | 'sessions' | 'cases' | 'events';
const CASE_PAGE_SIZE = 20;
const SESSION_PAGE_SIZE = 20;
const EVENT_PAGE_SIZE = 50;

const tabs: Array<{ key: AuditTab; label: string }> = [
  { key: 'overview', label: '审计总览' },
  { key: 'sessions', label: '会话审计' },
  { key: 'cases', label: '风险案件' },
  { key: 'events', label: '事件检索' },
];

const severityStyle: Record<SecurityRiskCase['severity'], string> = {
  low: 'bg-slate-100 text-slate-700',
  medium: 'bg-amber-100 text-amber-700',
  high: 'bg-orange-100 text-orange-700',
  critical: 'bg-red-100 text-red-700',
};

const statusLabel: Record<SecurityRiskCase['status'], string> = {
  open: '待研判',
  confirmed: '已确认',
  false_positive: '误报',
  accepted_risk: '已接受',
  resolved: '已处置',
};

// 处置动作二次确认文案
const reviewConfirmText: Record<'confirmed' | 'false_positive' | 'accepted_risk' | 'resolved', string> = {
  confirmed: '确认该案件为真实风险？确认后状态将标记为「已确认」。',
  false_positive: '确认将该案件标记为「误报」？',
  accepted_risk: '确认「接受风险」？接受后将不再提示处置。',
  resolved: '确认将该案件标记为「已处置」？',
};

const eventLabel: Record<string, string> = {
  file_action: '文件读取',
  taint_transition: '标签传递',
  network_action: '网络连接',
  policy_decision: '策略判定',
  enforcement_state: '执行状态',
};

// Risk conclusions come from the policy DSL `because` clause, which is authored
// in English on the backend. Translate the known rule reasons to Chinese for
// display; unknown reasons fall back to the original text unchanged.
const ruleReasonZh: Record<string, string> = {
  'credential-derived data reached an untrusted network target': '凭据衍生数据访问了不可信网络目标',
  'credential reached an untrusted target': '凭据数据访问了不可信目标',
  'credential taint reached unknown public endpoint': '凭据污点数据到达未知公网目标',
  'agentsight sensitive file policy': 'AgentSight 敏感文件策略',
};

function translateRuleReason(reason: string): string {
  if (!reason) return reason;
  const key = reason.trim().toLowerCase();
  return ruleReasonZh[key] ?? reason;
}

interface ProcessTreeNode {
  pid: number;
  ppid: number | null;
  labels: string[];
  children: ProcessTreeNode[];
  hasEvents: boolean;
}

// Reconstructs the pid -> ppid hierarchy for one case from its evidence events.
//
// Primary parent source: `identity.ppid`, captured by the enforcer on the real
// ActPlane path. Fallback: when a real ppid is unavailable (e.g. mock/dev data
// or the source event whose ppid is intentionally omitted), parent edges are
// derived from taint *inheritance* events, where a child process inherits a
// label from its parent (source_pid -> target_pid). A process referenced only
// as a parent (no evidence of its own, or whose ppid is outside the set) becomes
// the tree entry (root).
function buildProcessTree(evidence: SecurityEvidenceEvent[]): {
  roots: ProcessTreeNode[];
  count: number;
} {
  const nodes = new Map<number, ProcessTreeNode>();
  const ensure = (pid: number): ProcessTreeNode => {
    let node = nodes.get(pid);
    if (!node) {
      node = { pid, ppid: null, labels: [], children: [], hasEvents: false };
      nodes.set(pid, node);
    }
    return node;
  };
  const labelSets = new Map<number, Set<string>>();
  const addLabel = (pid: number, label: string) => {
    const set = labelSets.get(pid) ?? new Set<string>();
    set.add(label.toUpperCase());
    labelSets.set(pid, set);
  };

  for (const item of evidence) {
    const pid = Number(item.identity.pid);
    if (!Number.isFinite(pid) || pid <= 0) continue;
    const node = ensure(pid);
    node.hasEvents = true;
    const rawPpid = item.identity.ppid;
    if (typeof rawPpid === 'number' && rawPpid > 0 && rawPpid !== pid && node.ppid === null) {
      node.ppid = rawPpid;
    }
    if (item.event_type === 'taint_transition') {
      const label = item.event.label;
      if (typeof label === 'string' && label.trim()) addLabel(pid, label.trim());
    }
  }

  // Fallback parent edges from taint inheritance when no real ppid was captured.
  for (const item of evidence) {
    if (item.event_type !== 'taint_transition') continue;
    if (String(item.event.transition ?? '') !== 'inherit') continue;
    const sourcePid = Number(item.event.source_pid);
    const targetPid = Number(item.event.target_pid);
    if (!Number.isFinite(sourcePid) || !Number.isFinite(targetPid)) continue;
    if (sourcePid <= 0 || targetPid <= 0 || sourcePid === targetPid) continue;
    const child = ensure(targetPid);
    if (child.ppid === null) child.ppid = sourcePid;
  }

  // Materialize referenced parents so the entry process appears even without
  // any evidence of its own.
  for (const node of Array.from(nodes.values())) {
    if (node.ppid !== null) ensure(node.ppid);
  }
  for (const [pid, set] of labelSets) {
    const node = nodes.get(pid);
    if (node) node.labels = Array.from(set);
  }

  const roots: ProcessTreeNode[] = [];
  for (const node of nodes.values()) {
    if (node.ppid !== null && nodes.has(node.ppid) && node.ppid !== node.pid) {
      nodes.get(node.ppid)!.children.push(node);
    } else {
      roots.push(node);
    }
  }
  const sortNodes = (list: ProcessTreeNode[]) => {
    list.sort((left, right) => left.pid - right.pid);
    list.forEach((node) => sortNodes(node.children));
  };
  sortNodes(roots);
  return { roots, count: nodes.size };
}

function flattenProcessTree(
  nodes: ProcessTreeNode[],
  depth: number,
  out: Array<{ node: ProcessTreeNode; depth: number }>,
): void {
  for (const node of nodes) {
    out.push({ node, depth });
    flattenProcessTree(node.children, depth + 1, out);
  }
}

function formatTime(timestampNs: number): string {
  if (!timestampNs) return '—';
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(timestampNs / 1_000_000);
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : '系统审计数据加载失败';
}

function decisionText(detail: SecurityRiskCaseDetail): string {
  const decision = detail.evidence.find((item) => item.event_type === 'policy_decision');
  const mode = decision?.event.mode;
  const blocked = decision?.event.blocked === true || detail.blocked;
  if (blocked) return '内核已拦截';
  if (mode === 'enforce') return '请求拦截，但未确认内核阻断';
  if (mode === 'audit') return '规则命中，已放行';
  return '仅观测，未执行拦截';
}

function evidenceSummary(item: SecurityEvidenceEvent): string {
  switch (item.event_type) {
    case 'file_action':
      return String(item.event.path ?? item.event.operation ?? '敏感文件访问');
    case 'taint_transition':
      return `${String(item.event.label ?? 'SENSITIVE')} · ${String(item.event.transition ?? 'add')}`;
    case 'network_action':
      return String(item.event.destination ?? '未知网络目标');
    case 'policy_decision':
      return String(item.event.reason ?? item.event.mode ?? '策略完成判定');
    default:
      return String(item.event.message ?? '系统事件');
  }
}

function containmentEligible(riskCase: SecurityRiskCase): boolean {
  return (riskCase.severity === 'high' || riskCase.severity === 'critical')
    && riskCase.status !== 'false_positive'
    && riskCase.status !== 'accepted_risk'
    && riskCase.status !== 'resolved';
}

const StatCard: React.FC<{
  label: string;
  value: React.ReactNode;
  hint: string;
  onClick?: () => void;
  active?: boolean;
}> = ({ label, value, hint, onClick, active }) => {
  const interactive = typeof onClick === 'function';
  return (
    <div
      onClick={onClick}
      role={interactive ? 'button' : undefined}
      tabIndex={interactive ? 0 : undefined}
      onKeyDown={interactive ? (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onClick!();
        }
      } : undefined}
      className={`rounded-xl border bg-white p-4 shadow-sm ${
        interactive ? 'cursor-pointer transition hover:border-blue-300 hover:shadow-md' : ''
      } ${active ? 'border-blue-400 ring-1 ring-blue-200' : 'border-gray-200'}`}
    >
      <p className="text-sm text-gray-500">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-gray-900">{value}</p>
      <p className="mt-1 text-xs text-gray-400">{hint}</p>
    </div>
  );
};

const Pagination: React.FC<{
  offset: number;
  pageSize: number;
  total: number;
  loading: boolean;
  onChange: (offset: number) => void;
}> = ({ offset, pageSize, total, loading, onChange }) => {
  const page = Math.floor(offset / pageSize) + 1;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="flex items-center justify-between border-t border-gray-200 px-5 py-3 text-xs text-gray-500">
      <span>{offset + 1}–{Math.min(offset + pageSize, total)} / {total}</span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={offset === 0 || loading}
          onClick={() => onChange(Math.max(0, offset - pageSize))}
          className="rounded border px-2 py-1 disabled:text-gray-300"
        >
          上一页
        </button>
        <span>{page}/{pageCount}</span>
        <button
          type="button"
          disabled={offset + pageSize >= total || loading}
          onClick={() => onChange(offset + pageSize)}
          className="rounded border px-2 py-1 disabled:text-gray-300"
        >
          下一页
        </button>
      </div>
    </div>
  );
};

export const SystemAuditPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState<AuditTab>('overview');
  const [summary, setSummary] = useState<SecuritySummary | null>(null);
  const [cases, setCases] = useState<SecurityRiskCase[]>([]);
  const [caseTotal, setCaseTotal] = useState(0);
  const [caseOffset, setCaseOffset] = useState(0);
  const [sessions, setSessions] = useState<SecuritySessionSummary[]>([]);
  const [sessionTotal, setSessionTotal] = useState(0);
  const [sessionOffset, setSessionOffset] = useState(0);
  const [events, setEvents] = useState<SecurityEventRecord[]>([]);
  const [eventTotal, setEventTotal] = useState(0);
  const [eventOffset, setEventOffset] = useState(0);
  const [selectedCase, setSelectedCase] = useState<SecurityRiskCaseDetail | null>(null);
  const [bindings, setBindings] = useState<EnforcementBinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState('');
  const [reviewing, setReviewing] = useState(false);
  const [containmentDialogOpen, setContainmentDialogOpen] = useState(false);
  const [caseStatusFilter, setCaseStatusFilter] = useState<'all' | SecurityReviewStatus>('all');
  const [caseBlockedOnly, setCaseBlockedOnly] = useState(false);
  const [caseSort, setCaseSort] = useState<'time' | 'risk'>('time');
  const [caseAgentFilter, setCaseAgentFilter] = useState<string | null>(() => searchParams.get('agent_id'));
  const [eventNextOffset, setEventNextOffset] = useState<number | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const caseRequestVersion = useRef(0);
  const reviewRequestVersion = useRef(0);
  const loadRequestVersion = useRef(0);

  const load = useCallback(async () => {
    loadRequestVersion.current += 1;
    const version = loadRequestVersion.current;
    setLoading(true);
    const results = await Promise.allSettled([
      fetchAuditSummary({ limit: 10 }),
      fetchSecurityCases({ limit: CASE_PAGE_SIZE, offset: caseOffset }),
      fetchAuditSessions({ limit: SESSION_PAGE_SIZE, offset: sessionOffset }),
      fetchAuditEvents({ limit: EVENT_PAGE_SIZE, offset: eventOffset, include_details: true }),
      fetchEnforcementBindings(),
    ]);
    if (loadRequestVersion.current !== version) return;
    const failures = results.filter((result) => result.status === 'rejected');
    if (results[0].status === 'fulfilled') setSummary(results[0].value.data);
    if (results[1].status === 'fulfilled') {
      setCases(results[1].value.data.items);
      setCaseTotal(results[1].value.data.total);
    }
    if (results[2].status === 'fulfilled') {
      setSessions(results[2].value.data.items);
      setSessionTotal(results[2].value.data.total);
    }
    if (results[3].status === 'fulfilled') {
      setEvents(results[3].value.data.items);
      setEventTotal(results[3].value.data.total);
      setEventNextOffset(results[3].value.data.next_offset ?? null);
    }
    if (results[4].status === 'fulfilled') {
      setBindings(results[4].value.bindings);
    }
    setError(failures.length ? errorText((failures[0] as PromiseRejectedResult).reason) : '');
    setLoading(false);
  }, [caseOffset, eventOffset, sessionOffset]);

  useEffect(() => {
    void load();
  }, [load]);

  const openCase = async (caseId: string) => {
    caseRequestVersion.current += 1;
    reviewRequestVersion.current += 1;
    const version = caseRequestVersion.current;
    setContainmentDialogOpen(false);
    setSelectedCase(null);
    setDetailLoading(true);
    setError('');
    setReviewing(false);
    try {
      const response = await fetchSecurityCase(caseId);
      if (caseRequestVersion.current !== version) return;
      setSelectedCase(response.data);
    } catch (nextError) {
      if (caseRequestVersion.current === version) setError(errorText(nextError));
    } finally {
      if (caseRequestVersion.current === version) setDetailLoading(false);
    }
  };

  const refresh = async () => {
    const selectedCaseId = selectedCase?.case_id;
    const version = caseRequestVersion.current;
    await load();
    if (selectedCaseId && caseRequestVersion.current === version) await openCase(selectedCaseId);
  };

  const handleContained = async (caseId: string) => {
    const version = caseRequestVersion.current;
    setContainmentDialogOpen(false);
    await load();
    if (caseRequestVersion.current === version) await openCase(caseId);
  };

  const review = async (
    status: 'confirmed' | 'false_positive' | 'accepted_risk' | 'resolved',
  ) => {
    if (!selectedCase) return;
    if (!window.confirm(reviewConfirmText[status])) return;
    reviewRequestVersion.current += 1;
    const reviewVersion = reviewRequestVersion.current;
    const caseVersion = caseRequestVersion.current;
    const caseId = selectedCase.case_id;
    setReviewing(true);
    try {
      await reviewSecurityCase(caseId, status);
      if (
        reviewRequestVersion.current !== reviewVersion
        || caseRequestVersion.current !== caseVersion
      ) return;
      await load();
      if (caseRequestVersion.current === caseVersion) await openCase(caseId);
    } catch (nextError) {
      if (
        reviewRequestVersion.current === reviewVersion
        && caseRequestVersion.current === caseVersion
      ) setError(errorText(nextError));
    } finally {
      if (
        reviewRequestVersion.current === reviewVersion
        && caseRequestVersion.current === caseVersion
      ) setReviewing(false);
    }
  };

  const totalCases = summary?.risk_cases_total ?? caseTotal;
  const openCases = summary?.risk_cases_open ?? 0;
  const blockedCases = summary?.risk_cases_blocked ?? 0;
  const sortedEvidence = useMemo(() => (
    selectedCase ? [...selectedCase.evidence].sort((left, right) => (
      left.occurred_at_ns - right.occurred_at_ns
    )) : []
  ), [selectedCase]);
  const processTree = useMemo(() => buildProcessTree(sortedEvidence), [sortedEvidence]);
  // 当前案件对应 agent 的活跃保护状态：匹配 enforced/pending/degraded binding。
  // mode 含 enforce → 拦截保护；含 audit/observe → 审计保护；无活跃 binding → 未保护。
  const caseProtection = useMemo<'enforce' | 'audit' | 'none'>(() => {
    if (!selectedCase) return 'none';
    const active = bindings.filter((binding) => (
      binding.request.agent_id === selectedCase.agent_id
      && (binding.state === 'enforced' || binding.state === 'pending' || binding.state === 'degraded')
    ));
    if (active.length === 0) return 'none';
    if (active.some((binding) => binding.request.policy_mode === 'enforce')) return 'enforce';
    return 'audit';
  }, [bindings, selectedCase]);
  const displayedCases = useMemo(() => {
    let list = cases;
    if (caseAgentFilter) list = list.filter((item) => item.agent_id === caseAgentFilter);
    if (caseStatusFilter !== 'all') list = list.filter((item) => item.status === caseStatusFilter);
    if (caseBlockedOnly) list = list.filter((item) => item.blocked);
    const sorted = [...list];
    if (caseSort === 'risk') sorted.sort((left, right) => right.risk_score - left.risk_score);
    else sorted.sort((left, right) => right.updated_at_ns - left.updated_at_ns);
    return sorted;
  }, [cases, caseAgentFilter, caseStatusFilter, caseBlockedOnly, caseSort]);
  const flatProcessTree = useMemo(() => {
    const out: Array<{ node: ProcessTreeNode; depth: number }> = [];
    flattenProcessTree(processTree.roots, 0, out);
    return out;
  }, [processTree]);

  // URL 参数: case_id 自动展开
  useEffect(() => {
    const caseIdParam = searchParams.get('case_id');
    if (caseIdParam && cases.length > 0) {
      const match = cases.find((c) => c.case_id === caseIdParam);
      if (match) {
        setActiveTab('cases');
        void openCase(match.case_id);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cases]);

  const loadMoreEvents = async () => {
    if (eventNextOffset === null || loadingMore) return;
    setLoadingMore(true);
    try {
      const result = await fetchAuditEvents({ limit: EVENT_PAGE_SIZE, offset: eventNextOffset, include_details: true });
      setEvents((prev) => [...prev, ...result.data.items]);
      setEventTotal(result.data.total);
      setEventNextOffset(result.data.next_offset ?? null);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setLoadingMore(false);
    }
  };

  const clearAgentFilter = () => {
    setCaseAgentFilter(null);
    const next = new URLSearchParams(searchParams);
    next.delete('agent_id');
    setSearchParams(next);
  };

  return (
    <div className="mx-auto w-full max-w-screen-2xl space-y-5 p-6">
      <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-gray-900">系统审计</h1>
            <span className="rounded-full bg-blue-100 px-2.5 py-1 text-xs font-semibold text-blue-700">
              AgentSight 本地数据
            </span>
          </div>
          <p className="mt-1 text-sm text-gray-500">
            从 Agent 会话出发，关联工具调用、进程、文件、网络和策略判定，形成可追溯证据链。
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => navigate('/security')}
            className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm text-gray-700"
          >
            查看原始事件
          </button>
          <button
            type="button"
            onClick={() => void refresh()}
            disabled={loading}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:bg-blue-300"
          >
            {loading ? '刷新中...' : '刷新'}
          </button>
        </div>
      </header>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      <section className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard label="审计事件" value={summary?.total ?? 0} hint="文件 / 标签 / 网络 / 判定" />
        <StatCard label="关联会话" value={summary?.affected_sessions ?? sessions.length} hint="具备系统行为证据" />
        <StatCard label="风险案件" value={totalCases} hint="规则关联后形成案件" />
        <StatCard
          label="待研判"
          value={openCases}
          hint="点击筛选待研判案件"
          onClick={() => { setActiveTab('cases'); setCaseBlockedOnly(false); setCaseStatusFilter('open'); }}
          active={activeTab === 'cases' && caseStatusFilter === 'open' && !caseBlockedOnly}
        />
        <StatCard
          label="确认拦截"
          value={blockedCases}
          hint="点击筛选已拦截案件"
          onClick={() => { setActiveTab('cases'); setCaseStatusFilter('all'); setCaseBlockedOnly(true); }}
          active={activeTab === 'cases' && caseBlockedOnly}
        />
      </section>

      <div className="flex gap-1 rounded-xl border border-gray-200 bg-white p-1 shadow-sm">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => setActiveTab(tab.key)}
            className={`rounded-lg px-4 py-2 text-sm font-medium ${
              activeTab === tab.key ? 'bg-blue-600 text-white' : 'text-gray-600 hover:bg-gray-50'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {(activeTab === 'overview' || activeTab === 'cases') && (
        <section className="grid min-h-[520px] grid-cols-1 gap-5 xl:grid-cols-[minmax(360px,0.85fr)_minmax(0,1.65fr)]">
          <div className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
            <div className="border-b border-gray-200 px-5 py-4">
              <h2 className="font-semibold text-gray-900">风险案件</h2>
              <p className="mt-1 text-xs text-gray-500">选择案件查看完整、按时序排列的原始证据。</p>
              <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
                <select
                  value={caseStatusFilter}
                  onChange={(event) => setCaseStatusFilter(event.target.value as 'all' | SecurityReviewStatus)}
                  className="rounded border border-gray-300 bg-white px-2 py-1 text-gray-700"
                >
                  <option value="all">全部状态</option>
                  <option value="open">待研判</option>
                  <option value="confirmed">已确认</option>
                  <option value="false_positive">误报</option>
                  <option value="accepted_risk">已接受</option>
                  <option value="resolved">已处置</option>
                </select>
                <select
                  value={caseSort}
                  onChange={(event) => setCaseSort(event.target.value as 'time' | 'risk')}
                  className="rounded border border-gray-300 bg-white px-2 py-1 text-gray-700"
                >
                  <option value="time">按时间</option>
                  <option value="risk">按风险分</option>
                </select>
                <label className="flex items-center gap-1 text-gray-600">
                  <input type="checkbox" checked={caseBlockedOnly} onChange={(event) => setCaseBlockedOnly(event.target.checked)} />
                  仅已拦截
                </label>
                {(caseStatusFilter !== 'all' || caseBlockedOnly) && (
                  <button
                    type="button"
                    onClick={() => { setCaseStatusFilter('all'); setCaseBlockedOnly(false); }}
                    className="text-blue-600"
                  >
                    清除筛选
                  </button>
                )}
                {caseAgentFilter && (
                  <span className="inline-flex items-center gap-1 rounded-full bg-blue-100 px-2 py-0.5 text-xs text-blue-700">
                    已按 Agent: {caseAgentFilter} 过滤
                    <button type="button" onClick={clearAgentFilter} className="ml-0.5 text-blue-500 hover:text-blue-800">✕</button>
                  </span>
                )}
              </div>
            </div>
            <div className="divide-y divide-gray-100">
              {displayedCases.length === 0 ? (
                <p className="px-5 py-12 text-center text-sm text-gray-400">
                  {cases.length === 0 ? '暂无风险案件' : '当前筛选条件下暂无案件'}
                </p>
              ) : displayedCases.map((item) => (
                <button
                  key={item.case_id}
                  type="button"
                  onClick={() => void openCase(item.case_id)}
                  className={`block w-full px-5 py-4 text-left hover:bg-gray-50 ${
                    selectedCase?.case_id === item.case_id ? 'bg-blue-50' : ''
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="font-medium text-gray-900">{translateRuleReason(item.summary)}</p>
                      <p className="mt-1 text-xs text-gray-500">
                        {item.agent_id} · {item.session_id || '无会话'} · {formatTime(item.updated_at_ns)}
                      </p>
                    </div>
                    <span className={`rounded-full px-2 py-1 text-xs font-semibold ${severityStyle[item.severity]}`}>
                      {item.risk_score}
                    </span>
                  </div>
                  <div className="mt-3 flex items-center gap-2 text-xs">
                    <span className="rounded bg-gray-100 px-2 py-1 text-gray-600">{statusLabel[item.status]}</span>
                    <span className={item.blocked ? 'text-red-600' : 'text-amber-600'}>
                      {item.blocked ? '内核已拦截' : '未确认阻断'}
                    </span>
                  </div>
                </button>
              ))}
            </div>
            {caseTotal > CASE_PAGE_SIZE && (
              <PaginationNew
                total={caseTotal}
                limit={CASE_PAGE_SIZE}
                offset={caseOffset}
                onPageChange={setCaseOffset}
              />
            )}
          </div>

          <div className="rounded-xl border border-gray-200 bg-white shadow-sm">
            {!selectedCase ? (
              <div className="flex h-full min-h-[420px] items-center justify-center text-sm text-gray-400">
                {detailLoading ? '正在加载证据链...' : '请选择一个风险案件'}
              </div>
            ) : (
              <div>
                <div className="border-b border-gray-200 p-5">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <p className="text-xs font-medium text-gray-500">风险结论</p>
                      <div className="mt-1 flex flex-wrap items-center gap-2">
                        <h2 className="text-xl font-semibold text-gray-900">{translateRuleReason(selectedCase.summary)}</h2>
                        {caseProtection === 'enforce' ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-700">拦截保护中</span>
                        ) : caseProtection === 'audit' ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-700">审计保护中</span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600">未保护</span>
                        )}
                      </div>
                      <p className="mt-2 text-sm text-gray-600">
                        {decisionText(selectedCase)} · 风险分 {selectedCase.risk_score} · 策略修订 #{selectedCase.policy_revision}
                      </p>
                    </div>
                    <button
                      type="button"
                      disabled={reviewing || selectedCase.status === 'confirmed'}
                      onClick={() => void review('confirmed')}
                      className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white disabled:bg-gray-300"
                    >
                      确认风险
                    </button>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2 text-xs">
                    <button type="button" disabled={reviewing} onClick={() => void review('false_positive')} className="rounded border px-3 py-1.5 text-gray-600 disabled:opacity-40">标记误报</button>
                    <button type="button" disabled={reviewing} onClick={() => void review('accepted_risk')} className="rounded border px-3 py-1.5 text-gray-600 disabled:opacity-40">接受风险</button>
                    {!selectedCase.containment && (
                      <button type="button" disabled={reviewing} onClick={() => void review('resolved')} className="rounded border px-3 py-1.5 text-gray-600 disabled:opacity-40">标记已处置</button>
                    )}
                    <button type="button" onClick={() => navigate(`/enforcement?highlight_binding=${selectedCase.containment?.binding_id || ''}&policy_id=${selectedCase.policy_id || ''}`)} className="rounded border border-blue-200 px-3 py-1.5 text-blue-700">查看拦截策略</button>
                  </div>
                  {(containmentEligible(selectedCase) || selectedCase.containment) && (
                    <ContainmentLifecycleCard
                      action={selectedCase.containment}
                      loading={false}
                      error={false}
                      canUpgrade={containmentEligible(selectedCase)}
                      reviewing={reviewing}
                      onUpgrade={() => setContainmentDialogOpen(true)}
                      onResolve={() => void review('resolved')}
                    />
                  )}
                </div>
                {flatProcessTree.length > 0 && (
                  <div className="border-b border-gray-200 p-5">
                    <div className="flex items-center justify-between gap-3">
                      <h3 className="font-semibold text-gray-900">进程树</h3>
                      <span className="rounded-full bg-gray-100 px-2.5 py-1 text-xs font-medium text-gray-500">
                        {processTree.count} 个进程
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-gray-500">
                      根据 PID、PPID 与标签继承事件还原本次风险链路。
                    </p>
                    <div className="mt-4 space-y-3">
                      {flatProcessTree.map(({ node, depth }) => (
                        <div
                          key={node.pid}
                          className="flex items-start gap-2"
                          style={{ marginLeft: depth * 28 }}
                        >
                          {depth > 0 && (
                            <span className="mt-3 select-none font-mono text-base text-gray-300" aria-hidden="true">
                              ↳
                            </span>
                          )}
                          <div
                            className={`flex-1 rounded-lg border px-4 py-3 ${
                              depth === 0 ? 'border-gray-200 bg-white' : 'border-gray-200 bg-gray-50'
                            }`}
                          >
                            <p className="font-semibold text-gray-900">
                              {depth === 0 ? `PID ${node.pid}` : `子进程 · PID ${node.pid}`}
                            </p>
                            <p className="mt-0.5 text-xs text-gray-500">
                              {depth === 0 ? '进程树入口' : `父进程 PID ${node.ppid ?? '—'}`}
                            </p>
                            {node.labels.length > 0 && (
                              <div className="mt-2 flex flex-wrap gap-1.5">
                                {node.labels.map((label) => (
                                  <span
                                    key={label}
                                    className="rounded bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-800"
                                  >
                                    {label}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <div className="p-5">
                  <h3 className="font-semibold text-gray-900">完整证据链</h3>
                  <div className="mt-4 space-y-1">
                    {sortedEvidence.map((item, index) => (
                      <div key={item.event_id} className="relative flex gap-4 pb-5">
                        {index < sortedEvidence.length - 1 && <span className="absolute left-[11px] top-6 h-full w-px bg-gray-200" />}
                        <span className={`relative mt-1 h-6 w-6 shrink-0 rounded-full border-4 border-white ${
                          item.event_type === 'policy_decision' ? 'bg-red-500' : 'bg-blue-500'
                        }`} />
                        <div className="min-w-0 flex-1 rounded-lg border border-gray-200 px-4 py-3">
                          <div className="flex items-center justify-between gap-3">
                            <p className="font-medium text-gray-900">{eventLabel[item.event_type] || item.event_type}</p>
                            <span className="text-xs text-gray-400">PID {item.identity.pid}</span>
                          </div>
                          <p className="mt-1 break-all text-sm text-gray-600">{evidenceSummary(item)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>
      )}

      {activeTab === 'sessions' && (
        <section className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
          <div className="border-b px-5 py-4"><h2 className="font-semibold">会话审计</h2></div>
          <table className="w-full text-left text-sm">
            <thead className="bg-gray-50 text-xs text-gray-500"><tr><th className="px-5 py-3">会话</th><th>系统事件</th><th>时间范围</th><th>入口</th></tr></thead>
            <tbody className="divide-y">
              {sessions.map((session) => <tr key={session.session_id}>
                <td className="px-5 py-4 font-mono text-xs">{session.session_id}</td>
                <td>{session.security_event_count ?? 0}</td>
                <td>{formatTime(session.first_seen_ns ?? 0)} ～ {formatTime(session.last_seen_ns ?? 0)}</td>
                <td><button type="button" onClick={() => navigate('/security')} className="text-blue-600">查看时间线</button></td>
              </tr>)}
            </tbody>
          </table>
          {sessionTotal > SESSION_PAGE_SIZE && (
            <Pagination
              offset={sessionOffset}
              pageSize={SESSION_PAGE_SIZE}
              total={sessionTotal}
              loading={loading}
              onChange={setSessionOffset}
            />
          )}
        </section>
      )}

      {activeTab === 'events' && (
        <section className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
          <div className="flex items-center justify-between border-b px-5 py-4">
            <h2 className="font-semibold">事件检索</h2>
            <button type="button" onClick={() => navigate('/security')} className="text-sm text-blue-600">进入安全可观测</button>
          </div>
          <table className="w-full text-left text-sm">
            <thead className="bg-gray-50 text-xs text-gray-500"><tr><th className="px-5 py-3">类型</th><th>会话</th><th>PID</th><th>结果</th></tr></thead>
            <tbody className="divide-y">
              {events.map((event) => <tr key={event.event_id}>
                <td className="px-5 py-4">{eventLabel[String(event.event_type)] || event.event_type || '系统事件'}</td>
                <td className="font-mono text-xs">{event.session_id || '—'}</td>
                <td>{event.pid ?? '—'}</td>
                <td>{event.result || '—'}</td>
              </tr>)}
            </tbody>
          </table>
          {eventTotal > EVENT_PAGE_SIZE && (
            <Pagination
              offset={eventOffset}
              pageSize={EVENT_PAGE_SIZE}
              total={eventTotal}
              loading={loading}
              onChange={setEventOffset}
            />
          )}
          {eventNextOffset !== null && (
            <div className="border-t border-gray-200 px-5 py-3 text-center">
              <button
                type="button"
                disabled={loadingMore}
                onClick={() => void loadMoreEvents()}
                className="rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
              >
                {loadingMore ? '加载中...' : '加载更多'}
              </button>
            </div>
          )}
        </section>
      )}

      {selectedCase && (
        <ContainmentDialog
          caseId={selectedCase.case_id}
          open={containmentDialogOpen}
          onClose={() => setContainmentDialogOpen(false)}
          onContained={() => void handleContained(selectedCase.case_id)}
        />
      )}
    </div>
  );
};
