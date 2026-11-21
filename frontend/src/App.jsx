import React, { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Badge } from "@astryxdesign/core/Badge";
import { Dialog } from "@astryxdesign/core/Dialog";
import { Table, pixel } from "@astryxdesign/core/Table";
import { TextInput } from "@astryxdesign/core/TextInput";
import { Selector } from "@astryxdesign/core/Selector";
import { DateInput } from "@astryxdesign/core/DateInput";
import RelationshipLayers from "./RelationshipLayers.jsx";

const fmt = (v) =>
  v === undefined || v === null || v === "" ? "확인 불가" : String(v);
const statusLabel = (s) =>
  ({
    pending_review: "검토 필요",
    approved_for_simulated_response: "시뮬레이션 승인",
    ready: "준비됨",
    disabled: "비활성",
    error: "오류",
    inference_error: "추론 실패",
    ok: "정상 처리",
    missing_command: "명령줄 없음",
    model_unavailable: "모델 사용 불가",
    too_long: "입력 길이 초과",
    invalid_input: "유효하지 않은 입력",
    invalid_output: "유효하지 않은 결과",
    review: "검토 필요",
    below_threshold: "임계값 미만",
    success: "성공",
    failure: "실패",
  })[s] || fmt(s);
const src = (s) =>
  ({
    rule: "규칙",
    correlation: "상관분석",
    "semantic-baseline": "키워드 기준선",
  })[s] || fmt(s);
const kind = (e) =>
  Number(e.sysmon_event_id) === 1
    ? "Sysmon 1 · 프로세스"
    : Number(e.sysmon_event_id) === 3
      ? "Sysmon 3 · 네트워크"
      : e.outcome === "success"
        ? "인증 성공"
        : e.outcome === "failure"
          ? "인증 실패"
          : "유형 확인 불가";
const evs = (a) =>
  a.source_events?.length ? a.source_events : a.event_refs || [];
const batchFor = (data, id) =>
  data.analyses.find((a) => (a.detection_ids || []).includes(id));
function eventLinked(data, batch, det, event) {
  if (!(det.event_ids || []).includes(event.event_id)) return false;
  if ((batch.detection_ids || []).includes(det.detection_id)) return true;
  const scopes = new Set();
  for (const b of data.analyses)
    for (const e of evs(b))
      if (e.event_id === event.event_id)
        scopes.add(e.endpoint_group || b.analysis_id);
  return scopes.size === 1;
}
const severity = (score) =>
  score == null || !Number.isFinite(Number(score))
    ? "확인 불가"
    : Number(score) >= 70
      ? "높음"
      : Number(score) >= 40
        ? "중간"
        : "낮음";
const evidenceWidths = {
  time: 230,
  received: 230,
  host: 150,
  kind: 150,
  event_id: 360,
  source: 200,
  outcome: 100,
  related: 100,
  collector: 150,
  group: 220,
  input: 120,
};
const cols = (pairs, wide) =>
  pairs.map(([key, header, renderCell]) => ({
    key,
    header,
    ...(wide ? { width: pixel(evidenceWidths[key] || 120) } : {}),
    ...(renderCell ? { renderCell } : { renderCell: (row) => fmt(row[key]) }),
  }));
function DataTable({
  rows,
  columns,
  empty = "표시할 데이터가 없습니다.",
  wide = false,
}) {
  const duplicates = new Map();
  const keyed = rows.map((r) => {
    const e = r.event;
    const identity = e
      ? [
          "event",
          r.batch?.analysis_id,
          e.event_id,
          e.input_index,
          e.endpoint_group,
        ]
      : r.detection_id
        ? ["detection", r.detection_id]
        : r.endpoint_id
          ? ["endpoint", r.endpoint_id]
          : r.collector_id && !r.event_id
            ? ["collector", r.collector_id]
            : r.analysis_id
              ? ["analysis", r.analysis_id, r.event_id]
              : r.id
                ? ["id", r.id]
                : [
                    "event",
                    r.event_id,
                    r.input_index,
                    r.timestamp,
                    r.log_source,
                    r.received_at,
                    r.analyzed_at,
                  ];
    const key = JSON.stringify(identity),
      count = duplicates.get(key) || 0;
    duplicates.set(key, count + 1);
    return { ...r, _rowid: `${key}:${count}` };
  });
  return rows.length ? (
    <div
      className={`soc-table-wrap${wide ? " soc-evidence-table" : ""}`}
      role={wide ? "region" : undefined}
      aria-label={wide ? "관련 이벤트 표, 가로로 스크롤 가능" : undefined}
      tabIndex={wide ? 0 : undefined}
    >
      <Table
        data={keyed}
        idKey="_rowid"
        columns={cols(columns, wide)}
        density="compact"
      />
    </div>
  ) : (
    <p className="soc-empty">{empty}</p>
  );
}
function Panel({ title, children }) {
  return (
    <section className="soc-panel">
      <h2>{title}</h2>
      {children}
    </section>
  );
}
// Each block is one API-provided observation group, not a verified device or network node.
function AssetBoard({ endpoints, disabled }) {
  const visible = endpoints.slice(0, 6);
  if (!visible.length) {
    return <p className="soc-empty">관찰된 호스트 정보가 없습니다.</p>;
  }
  const positions = [
    [27, 38],
    [43, 44],
    [59, 50],
    [38, 58],
    [54, 64],
    [70, 70],
  ];
  return (
    <div className="soc-asset-board">
      <div className="soc-asset-stage" aria-label="호스트 관찰 입체 시각화">
        <svg
          className="soc-asset-plane"
          viewBox="0 0 700 350"
          preserveAspectRatio="none"
          aria-hidden="true"
        >
          <polygon
            points="350,61 650,165 350,277 50,165"
            fill="#10151a"
            stroke="#55656d"
            strokeWidth="1.5"
          />
          <polygon
            points="350,277 650,165 650,178 350,290 50,178 50,165"
            fill="#0a0d10"
            stroke="#3e4b51"
            strokeWidth="1"
          />
          <path
            d="M 118 165 L 350 249 L 582 165 M 207 112 L 493 218 M 493 112 L 207 218"
            fill="none"
            stroke="#26353c"
            strokeWidth="1"
          />
        </svg>
        {visible.map((endpoint, index) => {
          const level = severity(endpoint.highest_score);
          const tone =
            level === "높음" ? "high" : level === "중간" ? "medium" : "neutral";
          const label = fmt(endpoint.host);
          return (
            <div
              className={`soc-asset-node ${tone}`}
              key={endpoint.endpoint_id}
              style={{
                left: `${positions[index][0]}%`,
                top: `${positions[index][1]}%`,
              }}
            >
              <Button
                label={`${label} · 탐지 ${fmt(endpoint.detection_count)}건 · 호스트 상세`}
                href={
                  endpoint.endpoint_id
                    ? `/console/endpoints/${encodeURIComponent(endpoint.endpoint_id)}`
                    : undefined
                }
                isDisabled={disabled || !endpoint.endpoint_id}
                variant="ghost"
                className="soc-asset-cube-button"
                style={{
                  width: 58,
                  height: 70,
                  padding: 0,
                  backgroundColor: "transparent",
                }}
              >
                <svg
                  viewBox="0 0 64 74"
                  width="58"
                  height="70"
                  aria-hidden="true"
                  focusable="false"
                >
                  <polygon
                    className="soc-cube-top"
                    points="32,3 59,18 32,33 5,18"
                  />
                  <polygon
                    className="soc-cube-left"
                    points="5,18 32,33 32,68 5,53"
                  />
                  <polygon
                    className="soc-cube-right"
                    points="32,33 59,18 59,53 32,68"
                  />
                </svg>
              </Button>
              <span className="soc-asset-node-label" aria-hidden="true">
                {label}
              </span>
            </div>
          );
        })}
      </div>
      <div className="soc-asset-list">
        <div className="soc-asset-list-heading">
          <strong>호스트 관찰</strong>
          <span>
            표시 {visible.length} / {endpoints.length}
          </span>
        </div>
        {visible.map((endpoint) => (
          <div className="soc-asset-list-row" key={endpoint.endpoint_id}>
            <div>
              <Button
                label={fmt(endpoint.host)}
                href={
                  endpoint.endpoint_id
                    ? `/console/endpoints/${encodeURIComponent(endpoint.endpoint_id)}`
                    : undefined
                }
                isDisabled={disabled || !endpoint.endpoint_id}
                variant="ghost"
                size="sm"
              />
              <span className="soc-asset-list-meta">
                수집기 {fmt(endpoint.collector_id)} · 이벤트{" "}
                {fmt(endpoint.event_count)}건
              </span>
            </div>
            <span className="soc-asset-list-count">
              탐지 {fmt(endpoint.detection_count)}건<br />
              <small>
                {endpoint.highest_score == null
                  ? "점수 없음"
                  : `최고 ${severity(endpoint.highest_score)}`}
              </small>
            </span>
          </div>
        ))}
        <Button
          label="전체 호스트 관찰 보기"
          href="/console/endpoints"
          isDisabled={disabled}
          variant="ghost"
          size="sm"
        />
      </div>
    </div>
  );
}

function LinkButton({ label, onClick }) {
  return <Button label={label} variant="ghost" size="sm" onClick={onClick} />;
}

function Login() {
  const [username, setUsername] = useState(""),
    [password, setPassword] = useState(""),
    [status, setStatus] = useState(""),
    [busy, setBusy] = useState(false);
  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setStatus("로그인 중…");
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 15000);
    try {
      const r = await fetch("/api/v1/login", {
        method: "POST",
        credentials: "same-origin",
        signal: controller.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      setPassword("");
      if (!r.ok) {
        setStatus(
          r.status === 401
            ? "아이디 또는 비밀번호가 올바르지 않습니다."
            : "로그인 설정 또는 서버 연결을 확인하세요.",
        );
        return;
      }
      window.location.assign("/");
    } catch {
      setPassword("");
      setStatus(
        timedOut
          ? "로그인 요청 시간이 초과됐습니다 (15초)."
          : "서버에 연결하지 못했습니다.",
      );
    } finally {
      clearTimeout(timer);
      setBusy(false);
    }
  }
  return (
    <main className="soc-login">
      <section className="soc-login-panel">
        <p className="soc-muted">AEGIS-ON</p>
        <h1>분석가 로그인</h1>
        <form onSubmit={submit}>
          <TextInput
            label="아이디"
            value={username}
            onChange={setUsername}
            htmlName="username"
            isRequired
          />
          <TextInput
            label="비밀번호"
            type="password"
            value={password}
            onChange={setPassword}
            htmlName="password"
            isRequired
          />
          <Button
            type="submit"
            label="로그인"
            variant="primary"
            isLoading={busy}
          />
        </form>
        <p role="status" className="soc-error">
          {status}
        </p>
      </section>
    </main>
  );
}

export default function App() {
  const path = window.location.pathname;
  if (path === "/login") return <Login />;
  return <Console path={path} />;
}

function Console({ path }) {
  const [session, setSession] = useState(null),
    [data, setData] = useState({ analyses: [], detections: [] }),
    [endpoints, setEndpoints] = useState([]),
    [collectors, setCollectors] = useState([]),
    [endpoint, setEndpoint] = useState(null),
    [pii, setPii] = useState(null),
    [model, setModel] = useState(null);
  const [endpointSeen, setEndpointSeen] = useState(false),
    [failedApis, setFailedApis] = useState({}),
    [dialog, setDialog] = useState(null),
    [rationale, setRationale] = useState("");
  const [loaded, setLoaded] = useState(false),
    [status, setStatus] = useState("불러오는 중…"),
    [error, setError] = useState(false),
    [detail, setDetail] = useState(null),
    [collectorId, setCollectorId] = useState(""),
    [secret, setSecret] = useState(null),
    [copied, setCopied] = useState(false),
    [busy, setBusy] = useState(false),
    [query, setQuery] = useState(""),
    [level, setLevel] = useState("전체"),
    [source, setSource] = useState("전체"),
    [since, setSince] = useState(undefined),
    [until, setUntil] = useState(undefined);
  const detailElement = useRef(null),
    detailOpener = useRef(null);
  const sessionReady = useRef(false),
    refreshInFlight = useRef(false);
  const csrf = useRef(""),
    busyRef = useRef(false),
    seq = useRef(0),
    hadFailure = useRef(false),
    secretRef = useRef(null);
  const page = path.startsWith("/console/endpoints/")
    ? "endpoint"
    : path === "/console/endpoints"
      ? "endpoints"
      : path === "/console/events"
        ? "events"
        : path === "/console/detections"
          ? "detections"
          : path === "/console/history"
            ? "history"
            : "overview";
  const api = useCallback(async (url, options = {}) => {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 15000);
    try {
      const r = await fetch(url, {
        ...options,
        credentials: "same-origin",
        signal: controller.signal,
        headers: {
          ...(options.method && options.method !== "GET"
            ? { "X-CSRF-Token": csrf.current }
            : {}),
          ...options.headers,
        },
      });
      if (r.status === 401) {
        window.location.assign("/login");
        throw new Error("세션이 만료됐습니다. 다시 로그인하세요.");
      }
      if (!r.ok)
        throw new Error(
          r.status === 503
            ? "이력 저장소 또는 인증 설정을 확인하세요."
            : `요청 실패 (HTTP ${r.status})`,
        );
      return await r.json();
    } catch (e) {
      if (timedOut) throw new Error("서버 요청 시간이 초과됐습니다 (15초).");
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }, []);
  const refresh = useCallback(async () => {
    if (
      !sessionReady.current ||
      busyRef.current ||
      secretRef.current ||
      refreshInFlight.current
    )
      return;
    refreshInFlight.current = true;
    const n = ++seq.current;
    try {
      const requests = [["history", api("/api/v1/history")]];
      if (page === "overview" || page === "endpoints")
        requests.push(
          ["endpoints", api("/api/v1/endpoints")],
          ["collectors", api("/api/v1/collectors")],
        );
      if (page === "overview")
        requests.push(
          ["pii", api("/api/v1/pii/status")],
          ["model", api("/api/v1/attack-model/status")],
        );
      if (page === "endpoint")
        requests.push([
          "endpoint",
          api(
            "/api/v1/endpoints/" +
              encodeURIComponent(
                decodeURIComponent(path.slice("/console/endpoints/".length)),
              ),
          ),
        ]);
      const results = await Promise.allSettled(
        requests.map(([, promise]) => promise),
      );
      if (n !== seq.current || busyRef.current || secretRef.current) return;
      const byName = Object.fromEntries(
        requests.map(([name], i) => [name, results[i]]),
      );
      const history = byName.history;
      if (history.status === "rejected") throw history.reason;
      const h = history.value;
      setData({ analyses: h.analyses || [], detections: h.detections || [] });
      setLoaded(true);
      const failures = [],
        failed = {};
      for (const name of [
        "endpoints",
        "collectors",
        "pii",
        "model",
        "endpoint",
      ]) {
        const result = byName[name];
        if (!result) continue;
        if (result.status === "rejected") {
          failed[name] = true;
          failures.push(
            {
              endpoints: "호스트",
              collectors: "수집기",
              pii: "개인정보 모델",
              model: "공격 모델",
              endpoint: "호스트 상세",
            }[name],
          );
          if (name === "pii") setPii(null);
          if (name === "model") setModel(null);
          continue;
        }
        if (name === "endpoints") {
          setEndpoints(result.value.endpoints || []);
          setEndpointSeen(true);
        }
        if (name === "collectors") setCollectors(result.value.collectors || []);
        if (name === "pii") setPii(result.value);
        if (name === "model") setModel(result.value);
        if (name === "endpoint") setEndpoint(result.value);
      }
      setFailedApis(failed);
      if (failures.length) {
        setError(true);
        setStatus(
          `일부 정보 연결 오류: ${failures.join(", ")}. 이전 표시는 최신 정보가 아닐 수 있습니다. 5초 후 재시도합니다.`,
        );
        hadFailure.current = true;
      } else {
        setStatus(
          (hadFailure.current ? "화면 연결 복구됨. " : "화면 연결됨. ") +
            (h.analyses?.length
              ? `저장된 분석 ${h.analyses.length}건.`
              : "아직 분석된 이력이 없습니다.") +
            " 5초마다 갱신합니다.",
        );
        setError(false);
        hadFailure.current = false;
      }
    } catch (e) {
      if (n !== seq.current) return;
      hadFailure.current = true;
      setError(true);
      setStatus(
        "화면 연결 오류: " +
          e.message +
          " 5초 후 재연결을 시도합니다. 기존 표시는 최신 정보가 아닐 수 있습니다.",
      );
    } finally {
      refreshInFlight.current = false;
    }
  }, [api, page, path]);
  useEffect(() => {
    let mounted = true,
      requesting = false;
    const getSession = async () => {
      if (!mounted || requesting || sessionReady.current) return;
      requesting = true;
      try {
        const s = await api("/api/v1/session");
        if (!mounted) return;
        csrf.current = s.csrf_token;
        sessionReady.current = true;
        setSession(s);
        setError(false);
      } catch (e) {
        if (mounted) {
          setError(true);
          setStatus(
            "세션 확인 실패: " + e.message + " 5초 후 다시 시도합니다.",
          );
        }
      } finally {
        requesting = false;
      }
    };
    getSession();
    const timer = setInterval(getSession, 5000);
    return () => {
      mounted = false;
      clearInterval(timer);
      seq.current++;
    };
  }, [api]);
  useEffect(() => {
    if (!secret) return;
    const warn = (e) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [secret]);
  useEffect(() => {
    if (!session) return;
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => {
      clearInterval(timer);
      seq.current++;
    };
  }, [session, refresh]);
  const act = async (fn) => {
    if (busyRef.current || secretRef.current) return;
    busyRef.current = true;
    setBusy(true);
    seq.current++;
    try {
      await fn();
    } catch (e) {
      setError(true);
      setStatus(e.message);
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  };
  const logout = () =>
    act(async () => {
      await api("/api/v1/logout", { method: "POST" });
      window.location.assign("/login");
    });
  const approve = () => {
    if (detail?.type !== "detection") return;
    setRationale("");
    setDialog({ type: "approve", id: detail.id });
  };
  const confirmApproval = () => {
    const id = dialog?.id;
    if (!id) return;
    setDialog(null);
    act(async () => {
      const r = await api(
        `/api/v1/detections/${encodeURIComponent(id)}/approval`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ analyst: session.analyst.trim(), rationale }),
        },
      );
      if (r.simulation_only !== true)
        throw new Error("시뮬레이션 결과를 확인하지 못했습니다.");
      setStatus(
        "승인 시뮬레이션이 저장됐습니다. 실제 차단은 수행하지 않았습니다.",
      );
      setError(false);
      busyRef.current = false;
      await refresh();
    });
  };
  const showSecret = (r) => {
    secretRef.current = r.credential;
    setSecret({ collector_id: r.collector_id });
    setCopied(false);
    setStatus(
      "인증 정보는 화면에 표시되지 않습니다. 지금 복사해 안전하게 보관하세요.",
    );
  };
  const register = (e) => {
    e.preventDefault();
    act(async () => {
      try {
        const r = await api("/api/v1/collectors/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ collector_id: collectorId }),
        });
        setCollectorId("");
        showSecret(r);
      } catch (e) {
        throw new Error(
          e.message +
            " · 처리 결과가 불확실하면 수집기 목록을 확인하세요. 등록됐지만 인증 정보를 받지 못했다면 폐기 후 재발급해야 합니다.",
        );
      }
    });
  };
  const manage = (c) => {
    if (busyRef.current || secretRef.current) return;
    setDialog({ type: "manage", collector: c });
  };
  const confirmManagement = () => {
    const c = dialog?.collector;
    if (!c) return;
    const action = c.credential_state === "revoked" ? "reissue" : "revoke";
    setDialog(null);
    act(async () => {
      try {
        const r = await api(
          `/api/v1/collectors/${encodeURIComponent(c.collector_id)}/${action}`,
          { method: "POST" },
        );
        if (action === "reissue") showSecret(r);
        else {
          busyRef.current = false;
          await refresh();
        }
      } catch (e) {
        throw new Error(
          e.message +
            " · 처리 결과가 불확실하면 목록을 새로고침하세요. 새 인증 정보를 받지 못했다면 폐기 후 재발급해야 합니다.",
        );
      }
    });
  };
  const copy = async () => {
    try {
      if (!navigator.clipboard?.writeText) throw Error();
      await navigator.clipboard.writeText(secretRef.current);
      setCopied(true);
      setStatus("인증 정보를 클립보드에 복사했습니다. 안전한 곳에 보관하세요.");
      setError(false);
    } catch {
      setError(true);
      setStatus(
        "복사하지 못했습니다. 보안 연결 또는 로컬 브라우저에서 다시 시도하세요. 닫으면 폐기 후 재발급해야 합니다.",
      );
    }
  };
  const closeSecret = () => {
    secretRef.current = null;
    setSecret(null);
    setCopied(false);
    setDialog(null);
    refresh();
  };
  const allEvents = data.analyses
    .flatMap((batch) => evs(batch).map((event) => ({ batch, event })))
    .map((row, index) => ({
      ...row,
      _eventOrder: index,
      // The API treats timestamps without an offset as UTC.
      _eventTime:
        typeof row.event.timestamp === "string"
          ? Date.parse(
              /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(
                row.event.timestamp,
              )
                ? `${row.event.timestamp}Z`
                : row.event.timestamp,
            )
          : NaN,
      // Date.parse discards precision after milliseconds; retain it for ties.
      _subMillisecond:
        typeof row.event.timestamp === "string"
          ? (
              row.event.timestamp.match(
                /\.(\d+)(?:Z|[+-]\d{2}:?\d{2})?$/i,
              )?.[1] || ""
            ).slice(3)
          : "",
    }))
    .sort((a, b) => {
      const aValid = Number.isFinite(a._eventTime);
      const bValid = Number.isFinite(b._eventTime);
      if (aValid && bValid) {
        const byMillis = b._eventTime - a._eventTime;
        if (byMillis) return byMillis;
        const precision = Math.max(
          a._subMillisecond.length,
          b._subMillisecond.length,
        );
        const aFraction = a._subMillisecond.padEnd(precision, "0");
        const bFraction = b._subMillisecond.padEnd(precision, "0");
        return (
          (aFraction < bFraction ? 1 : aFraction > bFraction ? -1 : 0) ||
          a._eventOrder - b._eventOrder
        );
      }
      if (aValid !== bValid) return aValid ? -1 : 1;
      return a._eventOrder - b._eventOrder;
    });
  const endpointEventMatch = (e) => {
    const group = endpoint?.endpoint,
      ids = new Set(group?.analysis_ids || [group?.analysis_id]);
    const matches = allEvents.filter(
      ({ batch, event }) =>
        ids.has(batch.analysis_id) &&
        event.event_id === e.event_id &&
        (e.endpoint_group
          ? event.endpoint_group === e.endpoint_group
          : batch.analysis_id === group?.analysis_id) &&
        (e.input_index == null || event.input_index === e.input_index),
    );
    return matches.length === 1 ? matches[0] : null;
  };
  const openDetail = (next) => {
    if (!detail) detailOpener.current = document.activeElement;
    setDetail(next);
  };
  const closeDetail = () => {
    setDetail(null);
    const opener = detailOpener.current;
    detailOpener.current = null;
    requestAnimationFrame(() => opener?.isConnected && opener.focus());
  };
  useEffect(() => {
    if (detail && detailElement.current) {
      detailElement.current.scrollIntoView?.({ block: "start" });
      detailElement.current.focus({ preventScroll: true });
    }
  }, [detail]);
  const openDetection = (id) => openDetail({ type: "detection", id });
  const detectionColumns = [
    [
      "score",
      "심각도",
      (r) => (
        <Badge
          label={severity(r.score)}
          variant={
            { 높음: "error", 중간: "warning" }[severity(r.score)] || "neutral"
          }
        />
      ),
    ],
    [
      "title",
      "탐지 결과",
      (r) => (
        <LinkButton
          label={`${fmt(r.technique)} · ${fmt(r.title)}`}
          onClick={() => openDetection(r.detection_id)}
        />
      ),
    ],
    ["source", "출처", (r) => src(r.source)],
    ["status", "검토 상태", (r) => statusLabel(r.status)],
    [
      "analyzed_at",
      "분석 시각",
      (r) => fmt(batchFor(data, r.detection_id)?.analyzed_at),
    ],
  ];
  const eventColumns = [
    ["time", "발생 시각", (r) => fmt(r.event.timestamp)],
    ["received", "서버 수신 시각", (r) => fmt(r.batch.received_at)],
    ["host", "호스트", (r) => fmt(r.event.host)],
    ["kind", "종류", (r) => kind(r.event)],
    [
      "event_id",
      "이벤트 ID",
      (r) => (
        <LinkButton
          label={fmt(r.event.event_id)}
          onClick={() =>
            openDetail({
              type: "event",
              batchId: r.batch.analysis_id,
              eventId: r.event.event_id,
            })
          }
        />
      ),
    ],
    ["source", "출처", (r) => fmt(r.event.log_source)],
    ["outcome", "인증 결과", (r) => statusLabel(r.event.outcome)],
    [
      "related",
      "관련 경고",
      (r) =>
        `${data.detections.filter((d) => eventLinked(data, r.batch, d, r.event)).length}건`,
    ],
  ];
  const hostColumns = [
    ["collector_id", "수집기"],
    [
      "host",
      "호스트 표시",
      (r) => (
        <Button
          label={fmt(r.host)}
          href={"/console/endpoints/" + encodeURIComponent(r.endpoint_id)}
          variant="ghost"
          size="sm"
          isDisabled={!!secret}
        />
      ),
    ],
    ["event_count", "이벤트"],
    ["detection_count", "탐지"],
    [
      "highest_score",
      "최고 심각도",
      (r) => (r.highest_score == null ? "없음" : severity(r.highest_score)),
    ],
    ["last_seen", "마지막 이벤트"],
    ["analyzed_at", "분석 시각"],
  ];
  const historyColumns = [
    ["analyzed_at", "분석 시각"],
    ["input_type", "입력"],
    ["processed", "처리", (r) => fmt(r.summary?.processed)],
    [
      "related",
      "탐지",
      (r) =>
        data.detections.filter(
          (d) =>
            (r.detection_ids || []).includes(d.detection_id) ||
            evs(r).some((e) => eventLinked(data, r, d, e)),
        ).length,
    ],
    [
      "analysis_id",
      "분석 ID",
      (r) => (
        <LinkButton
          label={fmt(r.analysis_id)}
          onClick={() => openDetail({ type: "analysis", id: r.analysis_id })}
        />
      ),
    ],
  ];
  const collectorColumns = [
    ["collector_id", "수집기"],
    [
      "credential_state",
      "인증 상태",
      (r) =>
        r.registered
          ? r.credential_state === "revoked"
            ? "폐기됨 · 재발급 필요"
            : "활성 · PC 설정 확인 필요"
          : "등록되지 않은 기존 관찰",
    ],
    ["last_heartbeat_at", "마지막 보고"],
    [
      "reported_state",
      "보고 상태",
      (r) => {
        const age = Date.now() - Date.parse(r.last_heartbeat_at || "");
        const prior =
          Date.parse(r.last_heartbeat_at || "") <
          Date.parse(r.credential_changed_at || "");
        return `${{ running: "실행 보고", stopped: "중단 보고", error: "오류 보고" }[r.reported_state] || "보고 없음"}${prior ? " · 인증 변경 전 보고" : ""}${Number.isFinite(age) && age > 30000 ? " · 30초 이상 미보고" : ""}`;
      },
    ],
    ["last_received_at", "마지막 수신"],
    [
      "last_error_code",
      "오류 보고",
      (r) =>
        r.last_error_code
          ? `${r.last_error_code} · ${fmt(r.last_error_at)} (과거 보고)`
          : "보고된 오류 없음",
    ],
    [
      "action",
      "관리",
      (r) =>
        r.registered ? (
          <Button
            label={`${r.collector_id} ${r.credential_state === "revoked" ? "재발급" : "폐기"}`}
            size="sm"
            isDisabled={busy || !!secret}
            onClick={() => manage(r)}
          />
        ) : null,
    ],
  ];
  const collectorsPanel = (
    <Panel title="수집기 인증 및 보고">
      <p className="soc-muted">
        마지막 보고 상태는 PC 온라인 여부를 뜻하지 않습니다. 서버가 받지 못한
        오류는 확인할 수 없습니다. 재발급 전 인증된 요청은 이후에도 완료될 수
        있습니다.
      </p>
      {failedApis.collectors && (
        <p className="soc-error">
          수집기 정보를 불러오지 못했습니다. 이전 표시는 최신이 아닐 수
          있습니다.
        </p>
      )}
      {(!failedApis.collectors || collectors.length > 0) && (
        <DataTable
          rows={collectors}
          columns={collectorColumns}
          empty="등록되거나 보고된 수집기가 없습니다. 이벤트가 없다는 뜻은 아닙니다."
        />
      )}
      {secret ? (
        <section className="soc-details">
          <h3>인증 정보 발급 완료</h3>
          <p>
            {secret.collector_id} 인증 정보는 화면에 표시하지 않습니다. 지금
            복사해 안전하게 보관하세요.
          </p>
          <p>
            PC에서 수집기를 중지하고 새 자격 파일을 준비한 뒤 기존 ID·서버
            주소·커서를 유지해 재시작하세요. 적용 여부는 보고만으로 확정할 수
            없습니다.
          </p>
          <div className="soc-actions">
            <Button label="인증 정보 복사" onClick={copy} />
            <Button
              label="인증 정보 확인 완료"
              isDisabled={!copied}
              onClick={closeSecret}
            />
            <Button
              label="복사하지 않고 닫기"
              onClick={() => setDialog({ type: "discard" })}
            />
          </div>
        </section>
      ) : (
        <form className="soc-inline" onSubmit={register}>
          <TextInput
            label="수집기 식별자"
            value={collectorId}
            onChange={setCollectorId}
            placeholder="영문·숫자·-·_"
            isRequired
          />
          <Button label="수집기 등록" type="submit" isDisabled={busy} />
        </form>
      )}
    </Panel>
  );
  const currentDet =
    detail?.type === "detection"
      ? data.detections.find((d) => d.detection_id === detail.id)
      : null;
  const currentBatch =
    detail?.type === "event"
      ? data.analyses.find((a) => a.analysis_id === detail.batchId)
      : detail?.type === "analysis"
        ? data.analyses.find((a) => a.analysis_id === detail.id)
        : null;
  const currentEvent =
    detail?.type === "event" && currentBatch
      ? evs(currentBatch).find((e) => e.event_id === detail.eventId)
      : null;
  const related = currentDet
    ? allEvents.filter(({ batch, event }) =>
        eventLinked(data, batch, currentDet, event),
      )
    : [];
  const detailBox = detail ? (
    <section
      className="soc-panel soc-details"
      aria-label="상세 정보"
      ref={detailElement}
      tabIndex={-1}
    >
      <div className="soc-section-head">
        <h2>
          {detail.type === "detection"
            ? "탐지 상세"
            : detail.type === "event"
              ? "이벤트 상세"
              : "분석 상세"}
        </h2>
        <Button label="상세 닫기" onClick={closeDetail} />
      </div>
      {detail.type === "detection" ? (
        currentDet ? (
          <>
            <h3>
              {fmt(currentDet.technique)} · {fmt(currentDet.title)}
            </h3>
            <p>
              출처 {src(currentDet.source)} · 심각도{" "}
              {severity(currentDet.score)} · 점수 {fmt(currentDet.score)} ·
              호스트 {fmt(currentDet.host)}
            </p>
            <h3>탐지 근거</h3>
            <ul>
              {(currentDet.evidence || []).length ? (
                currentDet.evidence.map((v, i) => <li key={i}>{fmt(v)}</li>)
              ) : (
                <li>저장된 근거 없음</li>
              )}
            </ul>
            <h3>관련 이벤트 · 가명처리된 메타데이터</h3>
            <DataTable
              rows={related}
              wide
              columns={[
                ...eventColumns,
                ["collector", "수집기", (r) => fmt(r.event.collector_id)],
                [
                  "group",
                  "인증 그룹",
                  (r) => fmt(r.event.auth_correlation_group),
                ],
                ["input", "입력 인덱스", (r) => fmt(r.event.input_index)],
              ]}
              empty="저장된 이벤트 연결 정보가 없습니다."
            />
            <p>
              상태 {statusLabel(currentDet.status)} · 승인 조치는 실제 차단이
              아닌 시뮬레이션입니다. 화면은 5초 간격으로 갱신되며 현재 저장
              상태와 차이가 있을 수 있습니다.
            </p>
            {currentDet.approval && (
              <p>
                처리 {fmt(currentDet.approval.approved_at)} · 분석가{" "}
                {fmt(currentDet.approval.analyst)} · 사유{" "}
                {fmt(currentDet.approval.rationale)}
              </p>
            )}
            {currentDet.status !== "approved_for_simulated_response" && (
              <Button
                label="시뮬레이션 승인"
                onClick={approve}
                isDisabled={busy}
              />
            )}
          </>
        ) : (
          <p>탐지 결과를 찾을 수 없습니다.</p>
        )
      ) : detail.type === "event" ? (
        currentEvent ? (
          <>
            <p>
              이벤트 {fmt(currentEvent.event_id)} · 종류 {kind(currentEvent)} ·
              발생 {fmt(currentEvent.timestamp)} · 수신{" "}
              {fmt(currentBatch.received_at)}
            </p>
            <p>
              출처 {fmt(currentEvent.log_source)} · 수집기{" "}
              {fmt(currentEvent.collector_id)} · 호스트 {fmt(currentEvent.host)}{" "}
              · 인증 그룹 {fmt(currentEvent.auth_correlation_group)}
            </p>
            <h3>관련 경고</h3>
            <DataTable
              rows={data.detections.filter((d) =>
                eventLinked(data, currentBatch, d, currentEvent),
              )}
              columns={detectionColumns}
              empty="관련 경고가 없습니다."
            />
          </>
        ) : (
          <p>이벤트를 찾을 수 없습니다.</p>
        )
      ) : currentBatch ? (
        <>
          <p>
            분석 {fmt(currentBatch.analysis_id)} ·{" "}
            {fmt(currentBatch.analyzed_at)} · {fmt(currentBatch.input_type)}
          </p>
          <DataTable
            rows={evs(currentBatch).map((event) => ({
              batch: currentBatch,
              event,
            }))}
            columns={eventColumns}
          />
          <h3>관련 탐지</h3>
          <DataTable
            rows={data.detections.filter(
              (d) =>
                (currentBatch.detection_ids || []).includes(d.detection_id) ||
                evs(currentBatch).some((e) =>
                  eventLinked(data, currentBatch, d, e),
                ),
            )}
            columns={detectionColumns}
            empty="관련 탐지 없음"
          />
        </>
      ) : (
        <p>분석 이력을 찾을 수 없습니다.</p>
      )}
    </section>
  ) : null;
  const filtered = data.detections.filter((d) => {
    const day = String(batchFor(data, d.detection_id)?.analyzed_at || "").slice(
      0,
      10,
    );
    return (
      (level === "전체" || severity(d.score) === level) &&
      (source === "전체" || src(d.source) === source) &&
      (!query ||
        `${d.technique || ""} ${d.title || ""}`
          .toLowerCase()
          .includes(query.toLowerCase())) &&
      (!since || day >= since) &&
      (!until || day <= until)
    );
  });
  const modelRows = data.analyses.flatMap((b) =>
    (b.attack_model?.results || []).map((x) => ({
      ...x,
      analysis_id: b.analysis_id,
      analyzed_at: b.analyzed_at,
    })),
  );
  const shadowRows = data.analyses.flatMap((b) =>
    b.review_shadow ? [{ ...b.review_shadow, analyzed_at: b.analyzed_at }] : [],
  );
  const nav = [
    ["관제 개요", "/"],
    ["관제 자산", "/console/endpoints"],
    ["이벤트", "/console/events"],
    ["탐지", "/console/detections"],
    ["분석 이력", "/console/history"],
  ];
  return (
    <div className="soc-app">
      <Button label="본문으로 건너뛰기" href="#soc-main" className="soc-skip" />
      <aside className="soc-sidebar">
        <div className="soc-brand">
          AEGIS-ON <small>보안 관제</small>
        </div>
        <nav className="soc-nav" aria-label="주 메뉴">
          {nav.map(([label, href]) => (
            <Button
              key={href}
              label={label}
              href={href}
              variant="ghost"
              isDisabled={!!secret}
              aria-current={
                (page === "endpoint"
                  ? "/console/endpoints"
                  : path === "/console"
                    ? "/"
                    : path) === href
                  ? "page"
                  : undefined
              }
            />
          ))}
        </nav>
      </aside>
      <main id="soc-main" className="soc-main" tabIndex={-1}>
        <header className="soc-topbar">
          <div>
            <h1>
              {
                {
                  overview: "관제 개요",
                  endpoints: "관제 자산",
                  endpoint: "호스트 관찰",
                  events: "이벤트",
                  detections: "탐지",
                  history: "분석 이력",
                }[page]
              }
            </h1>
          </div>
          <div className="soc-actions">
            <span>분석가 {fmt(session?.analyst)}</span>
            <Button
              label="새로고침"
              onClick={refresh}
              isDisabled={!session || busy || !!secret}
            />
            <Button
              label="로그아웃"
              onClick={logout}
              isDisabled={!session || busy || !!secret}
            />
          </div>
        </header>
        <div className="soc-content">
          <p
            role="status"
            className={error ? "soc-status soc-error" : "soc-status"}
          >
            {status}
          </p>
          <p className="soc-muted">
            화면의 가명처리된 식별 정보도 다른 정보와 연결되거나 추측될 수
            있습니다. 공유와 보관에 주의하세요.
          </p>
          {!loaded ? (
            <p className="soc-empty">
              {error
                ? "저장된 정보를 불러오지 못했습니다."
                : "저장된 정보를 불러오는 중입니다."}
            </p>
          ) : null}
          {loaded && (
            <>
              {page === "overview" && (
                <>
                  <section className="soc-metrics">
                    {[
                      ["저장된 분석", data.analyses.length],
                      ["저장된 탐지", data.detections.length],
                      [
                        "높은 심각도",
                        data.detections.filter(
                          (d) => severity(d.score) === "높음",
                        ).length,
                      ],
                      ["호스트 관찰 묶음", endpoints.length],
                    ].map(([a, b]) => (
                      <div
                        key={a}
                        className={
                          a === "높은 심각도" && b > 0
                            ? "soc-metric-alert"
                            : undefined
                        }
                      >
                        <span>{a}</span>
                        <strong>
                          {a === "호스트 관찰 묶음" && !endpointSeen
                            ? "—"
                            : a === "호스트 관찰 묶음" && failedApis.endpoints
                              ? `${b} (이전 값)`
                              : loaded
                                ? b
                                : "—"}
                        </strong>
                      </div>
                    ))}
                  </section>
                  <Panel title="관제 자산">
                    <p className="soc-muted">
                      각 상자는 수집기와 호스트 이름별 관찰입니다. 배치는 이해를
                      돕는 표현이며 실제 장치의 연결 관계나 온라인 상태를
                      의미하지 않습니다.
                    </p>
                    {failedApis.endpoints && (
                      <p className="soc-error">
                        호스트 정보를 불러오지 못했습니다. 이전 표시는 최신이
                        아닐 수 있습니다.
                      </p>
                    )}
                    {(!failedApis.endpoints || endpoints.length > 0) && (
                      <>
                        <AssetBoard endpoints={endpoints} disabled={!!secret} />
                        <RelationshipLayers
                          endpoints={endpoints}
                          history={data}
                          api={api}
                          disabled={!!secret}
                          onEvent={(batchId, eventId) =>
                            openDetail({ type: "event", batchId, eventId })
                          }
                          onDetection={openDetection}
                        />
                      </>
                    )}
                  </Panel>
                  <Panel title="최근 탐지">
                    <DataTable
                      rows={data.detections.slice(0, 8)}
                      columns={detectionColumns}
                      empty="저장된 탐지 결과가 없습니다."
                    />
                  </Panel>
                  <Panel title="최근 이벤트">
                    <DataTable
                      rows={allEvents.slice(0, 12)}
                      columns={eventColumns}
                      empty="저장된 이벤트가 없습니다."
                    />
                  </Panel>
                  <Panel title="모델 상태">
                    <p>
                      개인정보 탐지 {statusLabel(pii?.state)} · 정규식 별도 적용
                    </p>
                    <p>
                      공격 분석 모델 {statusLabel(model?.state)} · 실험용 명령줄
                      이진 분류. 점수는 공격 확률이 아닙니다.
                    </p>
                    <p>승인은 실제 차단이 아닌 시뮬레이션입니다.</p>
                  </Panel>
                  {collectorsPanel}
                </>
              )}
              {page === "endpoints" && (
                <>
                  <Panel title="호스트 관찰">
                    <p className="soc-muted">
                      수집기별 호스트명으로 묶습니다. 이름만으로 실제 장치
                      동일성은 확정할 수 없습니다.
                    </p>
                    {failedApis.endpoints && (
                      <p className="soc-error">
                        호스트 정보를 불러오지 못했습니다. 이전 표시는 최신이
                        아닐 수 있습니다.
                      </p>
                    )}
                    {(!failedApis.endpoints || endpoints.length > 0) && (
                      <DataTable
                        rows={endpoints}
                        columns={hostColumns}
                        empty="관찰된 호스트 정보가 없습니다."
                      />
                    )}
                  </Panel>
                  {collectorsPanel}
                </>
              )}
              {page === "endpoint" && (
                <Panel title="호스트 상세">
                  {failedApis.endpoint && (
                    <p className="soc-error">
                      호스트 상세 조회 실패. 이전 표시는 최신이 아닐 수
                      있습니다.
                    </p>
                  )}
                  {endpoint ? (
                    <>
                      <p>
                        수집기 {fmt(endpoint.endpoint?.collector_id)} · 호스트{" "}
                        {fmt(endpoint.endpoint?.host)} · 분류{" "}
                        {fmt(endpoint.endpoint?.attribution)} · 연결 상태 미수집
                      </p>
                      <h3>관련 이벤트</h3>
                      <DataTable
                        rows={endpoint.events || []}
                        columns={[
                          [
                            "event_id",
                            "이벤트 ID",
                            (r) => {
                              const match = endpointEventMatch(r);
                              return match ? (
                                <LinkButton
                                  label={fmt(r.event_id)}
                                  onClick={() =>
                                    openDetail({
                                      type: "event",
                                      batchId: match.batch.analysis_id,
                                      eventId: match.event.event_id,
                                    })
                                  }
                                />
                              ) : (
                                <span>
                                  {fmt(r.event_id)} · 미연결 (식별 근거 부족)
                                </span>
                              );
                            },
                          ],
                          ["timestamp", "발생 시각"],
                          ["received_at", "서버 수신 시각"],
                          ["log_source", "출처"],
                        ]}
                      />
                      <h3>관련 탐지</h3>
                      <DataTable
                        rows={endpoint.detections || []}
                        columns={detectionColumns}
                      />
                    </>
                  ) : (
                    <p>불러오는 중이거나 확인할 수 없습니다.</p>
                  )}
                </Panel>
              )}
              {page === "events" && (
                <Panel title="수집 이벤트">
                  <DataTable
                    rows={allEvents}
                    columns={eventColumns}
                    empty="수집된 이벤트 식별 정보가 없습니다."
                  />
                </Panel>
              )}
              {page === "detections" && (
                <>
                  <Panel title="탐지 목록">
                    <div className="soc-actions">
                      <Selector
                        label="심각도"
                        options={["전체", "높음", "중간", "낮음"]}
                        value={level}
                        onChange={setLevel}
                      />
                      <Selector
                        label="탐지 출처"
                        options={["전체", "규칙", "키워드 기준선", "상관분석"]}
                        value={source}
                        onChange={setSource}
                      />
                      <TextInput
                        label="탐지 유형"
                        value={query}
                        onChange={setQuery}
                      />
                      <DateInput
                        label="분석 날짜 시작 (UTC)"
                        value={since}
                        onChange={setSince}
                      />
                      <DateInput
                        label="분석 날짜 종료 (UTC)"
                        value={until}
                        onChange={setUntil}
                      />
                    </div>
                    <DataTable
                      rows={filtered}
                      columns={detectionColumns}
                      empty="조건에 맞는 탐지가 없습니다."
                    />
                  </Panel>
                  <Panel title="실험용 명령 모델 결과">
                    <p className="soc-muted">
                      이진 분류 결과이며 ATT&CK 기법이나 공격 확률을 예측하지
                      않습니다. 내부 판단 근거는 제공되지 않습니다.
                    </p>
                    <DataTable
                      rows={modelRows}
                      columns={[
                        ["analyzed_at", "분석 시각"],
                        ["event_id", "이벤트 ID"],
                        ["status", "상태", (r) => statusLabel(r.status)],
                        ["label", "분류", (r) => statusLabel(r.label)],
                        ["score", "모델 점수"],
                      ]}
                      empty="저장된 모델 결과가 없습니다."
                    />
                  </Panel>
                  <Panel title="CodeBERT 제안 순위">
                    <p className="soc-muted">
                      선택형 실험 모델 제안이며 기존 탐지 점수와 승인 상태는
                      바뀌지 않습니다. 별도 상관분석 경고는 순위에서 빠질 수
                      있습니다.
                    </p>
                    {shadowRows.length ? (
                      shadowRows.map((sh, i) => (
                        <div key={i}>
                          <p>
                            분석 {fmt(sh.analyzed_at)} · 모델{" "}
                            {statusLabel(sh.state)}
                            {sh.fixture ? " · 합성 검증용" : ""}
                          </p>
                          <DataTable
                            rows={sh.events || []}
                            columns={[
                              ["event_id", "이벤트 ID"],
                              [
                                "status",
                                "추론 상태",
                                (r) => statusLabel(r.status),
                              ],
                              ["score", "모델 점수"],
                            ]}
                          />
                          {sh.state === "ready" &&
                          (sh.events || []).some((e) => e.status === "ok") ? (
                            <DataTable
                              rows={(sh.proposed_order || [])
                                .map((id, rank) => ({
                                  id,
                                  rank: rank + 1,
                                  original:
                                    (sh.current_order || []).indexOf(id) + 1,
                                  detection: data.detections.find(
                                    (d) => d.detection_id === id,
                                  ),
                                }))
                                .filter((r) => r.detection)}
                              columns={[
                                [
                                  "rank",
                                  "기존 → 제안 순위",
                                  (r) =>
                                    `${r.original || "확인 불가"} → ${r.rank}`,
                                ],
                                [
                                  "detection",
                                  "탐지",
                                  (r) => (
                                    <LinkButton
                                      label={fmt(r.detection.title)}
                                      onClick={() => openDetection(r.id)}
                                    />
                                  ),
                                ],
                                [
                                  "evidence",
                                  "관련 이벤트 · 모델 결과",
                                  (r) =>
                                    (r.detection.event_ids || [])
                                      .map((id) => {
                                        const result = (sh.events || []).find(
                                          (e) => e.event_id === id,
                                        );
                                        return `${id} (${statusLabel(result?.status)}${Number.isFinite(result?.score) ? ` · ${result.score.toFixed(3)}` : ""})`;
                                      })
                                      .join(", ") || "관련 이벤트 없음",
                                ],
                              ]}
                            />
                          ) : (
                            <p>AI 제안이 없어 기존 경보 순서를 사용합니다.</p>
                          )}
                        </div>
                      ))
                    ) : (
                      <p>저장된 CodeBERT 결과가 없습니다.</p>
                    )}
                  </Panel>
                </>
              )}
              {page === "history" && (
                <>
                  <Panel title="분석 이력">
                    <DataTable
                      rows={data.analyses}
                      columns={historyColumns}
                      empty="저장된 분석 이력이 없습니다."
                    />
                  </Panel>
                  <Panel title="승인 시뮬레이션">
                    <p>실제 차단은 수행하지 않습니다.</p>
                    <DataTable
                      rows={data.detections.filter((d) => d.approval)}
                      columns={[
                        [
                          "title",
                          "탐지",
                          (r) => (
                            <LinkButton
                              label={fmt(r.title)}
                              onClick={() => openDetection(r.detection_id)}
                            />
                          ),
                        ],
                        [
                          "approved_at",
                          "처리 시각",
                          (r) => fmt(r.approval?.approved_at),
                        ],
                        ["analyst", "분석가", (r) => fmt(r.approval?.analyst)],
                        [
                          "rationale",
                          "사유",
                          (r) => fmt(r.approval?.rationale),
                        ],
                      ]}
                      empty="저장된 승인 시뮬레이션이 없습니다."
                    />
                  </Panel>
                </>
              )}
              {detailBox}
            </>
          )}
          <Dialog
            isOpen={!!dialog}
            onOpenChange={(open) => {
              if (!open) setDialog(null);
            }}
            aria-label={
              dialog?.type === "approve"
                ? "승인 시뮬레이션"
                : dialog?.type === "manage"
                  ? "수집기 인증 정보 변경"
                  : "인증 정보 닫기 확인"
            }
          >
            <div className="soc-panel">
              <h2>
                {dialog?.type === "approve"
                  ? "승인 시뮬레이션"
                  : dialog?.type === "manage"
                    ? "수집기 인증 정보 변경"
                    : "인증 정보 닫기 확인"}
              </h2>
              {dialog?.type === "approve" && (
                <>
                  <p>
                    실제 차단은 수행하지 않습니다. 화면은 5초 간격으로 갱신되며
                    지연될 수 있습니다. 승인 사유에 비밀값을 입력하지 마세요.
                  </p>
                  <TextInput
                    label="승인 사유"
                    value={rationale}
                    onChange={setRationale}
                  />
                </>
              )}
              {dialog?.type === "manage" && (
                <p>
                  {dialog.collector.collector_id}의 인증 정보를{" "}
                  {dialog.collector.credential_state === "revoked"
                    ? "재발급"
                    : "폐기"}
                  하시겠습니까? 기존 이력은 유지됩니다.
                </p>
              )}
              {dialog?.type === "discard" && (
                <p>
                  복사하지 않고 닫으면 인증 정보를 다시 볼 수 없습니다.
                  사용하려면 폐기 후 재발급해야 합니다.
                </p>
              )}
              <div className="soc-actions">
                <Button label="취소" onClick={() => setDialog(null)} />
                <Button
                  label={
                    dialog?.type === "approve"
                      ? "시뮬레이션 승인"
                      : dialog?.type === "manage"
                        ? dialog.collector.credential_state === "revoked"
                          ? "재발급"
                          : "폐기"
                        : "복사하지 않고 닫기"
                  }
                  variant="primary"
                  onClick={
                    dialog?.type === "approve"
                      ? confirmApproval
                      : dialog?.type === "manage"
                        ? confirmManagement
                        : closeSecret
                  }
                />
              </div>
            </div>
          </Dialog>
        </div>
      </main>
    </div>
  );
}
