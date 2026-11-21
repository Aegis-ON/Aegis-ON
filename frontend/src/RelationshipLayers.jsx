import React, { useEffect, useMemo, useState } from "react";
import { Button } from "@astryxdesign/core/Button";
import { Selector } from "@astryxdesign/core/Selector";

const display = (value) =>
  value == null || value === "" ? "확인 불가" : String(value);
const short = (value, limit = 23) => {
  const text = display(value);
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
};
const source = (value) =>
  ({
    rule: "규칙",
    correlation: "상관분석",
    "semantic-baseline": "키워드 기준선",
  })[value] || display(value);
const kind = (event) =>
  Number(event.sysmon_event_id) === 1
    ? "Sysmon 1 · 프로세스"
    : Number(event.sysmon_event_id) === 3
      ? "Sysmon 3 · 네트워크"
      : event.outcome === "success"
        ? "인증 성공"
        : event.outcome === "failure"
          ? "인증 실패"
          : "이벤트";
const eventRows = (batch) =>
  batch.source_events?.length ? batch.source_events : batch.event_refs || [];

// Require one globally unambiguous stored occurrence and membership in the
// selected API observation group before using a displayed ID as an edge.
export function buildRelationships(detail, history) {
  const group = detail?.endpoint;
  if (!group)
    return {
      events: [],
      detections: [],
      edges: [],
      excluded: 0,
      totalEvents: 0,
      totalDetections: 0,
    };
  const batches = Array.isArray(group.analysis_ids)
    ? group.analysis_ids
    : [group.analysis_id];
  const all = (history.analyses || []).flatMap((batch) =>
    eventRows(batch).map((event) => ({ batch, event })),
  );
  const eventsById = new Map();
  for (const row of all) {
    const id = row.event.event_id;
    const entries = eventsById.get(id) || [];
    entries.push(row);
    eventsById.set(id, entries);
  }
  const batchIds = new Set(batches);
  const matchedIds = new Set();
  let excluded = 0;
  const matched = [];
  for (const event of detail.events || []) {
    if (typeof event.event_id !== "string" || !event.event_id) {
      excluded++;
      continue;
    }
    const occurrences = eventsById.get(event.event_id) || [];
    if (occurrences.length !== 1 || matchedIds.has(event.event_id)) {
      excluded++;
      continue;
    }
    const row = occurrences[0];
    if (
      !batchIds.has(row.batch.analysis_id) ||
      (event.endpoint_group &&
        event.endpoint_group !== row.event.endpoint_group) ||
      (event.collector_id && event.collector_id !== row.event.collector_id) ||
      (event.input_index != null &&
        event.input_index !== row.event.input_index) ||
      (event.received_at && event.received_at !== row.batch.received_at)
    ) {
      excluded++;
      continue;
    }
    matchedIds.add(event.event_id);
    matched.push(row);
  }
  const events = matched.slice(0, 3);
  const detectionsById = new Map();
  for (const detection of history.detections || []) {
    const entries = detectionsById.get(detection.detection_id) || [];
    entries.push(detection);
    detectionsById.set(detection.detection_id, entries);
  }
  const seenDetections = new Set();
  const linked = [];
  for (const snapshot of detail.detections || []) {
    if (typeof snapshot.detection_id !== "string") continue;
    const current = detectionsById.get(snapshot.detection_id) || [];
    if (current.length !== 1 || seenDetections.has(snapshot.detection_id))
      continue;
    seenDetections.add(snapshot.detection_id);
    // Compare only the displayed IDs; never intersect two unbounded lists quadratically.
    const commonIds = new Set(
      events
        .map(({ event }) => event.event_id)
        .filter(
          (id) =>
            (snapshot.event_ids || []).includes(id) &&
            (current[0].event_ids || []).includes(id),
        ),
    );
    if (commonIds.size) linked.push({ detection: current[0], commonIds });
    if (linked.length === 3) break;
  }
  const displayed = linked.slice(0, 3);
  const detections = displayed.map((item) => item.detection);
  const edges = [];
  events.forEach((row, eventIndex) =>
    displayed.forEach((item, detectionIndex) => {
      if (item.commonIds.has(row.event.event_id))
        edges.push({ eventIndex, detectionIndex });
    }),
  );
  return {
    events,
    detections,
    edges,
    excluded,
    totalEvents: (detail.events || []).length,
    totalDetections: (detail.detections || []).length,
  };
}

function Cube({ x, y, color, label }) {
  return (
    <g transform={`translate(${x - 20} ${y - 45})`}>
      <polygon
        points="20,0 40,11 20,22 0,11"
        fill={color.top}
        stroke={color.line}
      />
      <polygon
        points="0,11 20,22 20,47 0,36"
        fill={color.left}
        stroke={color.line}
      />
      <polygon
        points="20,22 40,11 40,36 20,47"
        fill={color.right}
        stroke={color.line}
      />
      <text x="20" y="64" textAnchor="middle" className="soc-rel-node-label">
        {short(label, 18)}
      </text>
    </g>
  );
}
const neutral = {
  top: "#354950",
  left: "#1a292f",
  right: "#253a43",
  line: "#98abb1",
};
const eventColor = {
  top: "#314b53",
  left: "#182e34",
  right: "#244047",
  line: "#8eb0b5",
};
const alertColor = {
  top: "#604c36",
  left: "#3b3024",
  right: "#4d3c2b",
  line: "#d5bb90",
};
const hostPoint = { x: 375, y: 113 };
const positions = [
  [248, 224],
  [375, 248],
  [502, 272],
];
const detectionPositions = [
  [248, 390],
  [375, 414],
  [502, 438],
];

export default function RelationshipLayers({
  endpoints,
  history,
  api,
  onEvent,
  onDetection,
  disabled,
}) {
  const initial =
    endpoints.find((e) => e.detection_count > 0 && e.endpoint_id) ||
    endpoints.find((e) => e.endpoint_id);
  const [selected, setSelected] = useState(initial?.endpoint_id || "");
  const [detail, setDetail] = useState(null);
  const [state, setState] = useState("loading");
  useEffect(() => {
    if (!endpoints.some((e) => e.endpoint_id === selected))
      setSelected(initial?.endpoint_id || "");
  }, [endpoints, selected, initial?.endpoint_id]);
  useEffect(() => {
    if (!selected) {
      setDetail(null);
      setState("empty");
      return;
    }
    let active = true,
      pending = false;
    setDetail(null);
    setState("loading");
    const load = async () => {
      if (pending) return;
      pending = true;
      try {
        const next = await api(
          `/api/v1/endpoints/${encodeURIComponent(selected)}`,
        );
        if (active && next.endpoint?.endpoint_id === selected) {
          setDetail(next);
          setState("ready");
        } else if (active) {
          setDetail(null);
          setState("error");
        }
      } catch {
        if (active) {
          setDetail(null);
          setState("error");
        }
      } finally {
        pending = false;
      }
    };
    load();
    const timer = setInterval(load, 5000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [selected, api]);
  const graph = useMemo(
    () => buildRelationships(detail, history),
    [detail, history],
  );
  if (!endpoints.length) return null;
  return (
    <section className="soc-rel" aria-labelledby="soc-rel-title">
      <div className="soc-rel-heading">
        <div>
          <h3 id="soc-rel-title">관찰 근거 관계</h3>
          <p>관찰 묶음 → 포함 이벤트 → 탐지 근거</p>
        </div>
        <Selector
          label="관찰 묶음 선택"
          value={selected}
          onChange={setSelected}
          isDisabled={disabled}
          options={endpoints
            .filter((e) => e.endpoint_id)
            .map((e) => ({
              value: e.endpoint_id,
              label: `${display(e.host)} · ${display(e.collector_id)}`,
            }))}
        />
      </div>
      <p className="soc-rel-limit">
        선은 저장된 포함·근거 관계입니다. 통신 경로, 실제 기기 동일성 또는 공격
        순서를 뜻하지 않습니다.
      </p>
      {state === "loading" && (
        <p role="status">관련 근거를 불러오는 중입니다.</p>
      )}
      {state === "error" && (
        <p className="soc-error" role="status">
          관련 근거를 불러오지 못했습니다. 자동으로 다시 시도합니다.
        </p>
      )}
      {state === "ready" &&
        detail &&
        detail.endpoint?.endpoint_id === selected && (
          <>
            <div className="soc-rel-layout">
              <svg
                className="soc-rel-graph"
                viewBox="0 0 780 535"
                role="img"
                aria-label="선택한 호스트 관찰 묶음, 이벤트, 탐지의 저장된 관계. 아래 목록에서도 확인할 수 있습니다."
              >
                <g className="soc-rel-plane">
                  <polygon points="162,40 704,145 615,187 73,82" />
                  <polygon points="162,206 704,311 615,353 73,248" />
                  <polygon points="162,372 704,477 615,519 73,414" />
                </g>
                <g className="soc-rel-edges">
                  {graph.events.map((row, i) => (
                    <path
                      key={`host-${row.batch.analysis_id}-${row.event.event_id}`}
                      data-edge-type="observation-event"
                      d={`M ${hostPoint.x} ${hostPoint.y} L ${positions[i][0]} ${positions[i][1] - 34}`}
                    />
                  ))}
                  {graph.edges.map(({ eventIndex, detectionIndex }) => (
                    <path
                      key={`${eventIndex}-${detectionIndex}`}
                      data-edge-type="event-evidence"
                      d={`M ${positions[eventIndex][0]} ${positions[eventIndex][1]} L ${detectionPositions[detectionIndex][0]} ${detectionPositions[detectionIndex][1] - 34}`}
                    />
                  ))}
                </g>
                <text x="30" y="92" className="soc-rel-layer-label">
                  관찰 묶음
                </text>
                <text x="30" y="258" className="soc-rel-layer-label">
                  포함 이벤트
                </text>
                <text x="30" y="424" className="soc-rel-layer-label">
                  탐지 근거
                </text>
                <Cube
                  {...hostPoint}
                  color={neutral}
                  label={detail.endpoint.host}
                />
                {graph.events.map((row, i) => (
                  <Cube
                    key={`${row.batch.analysis_id}-${row.event.event_id}`}
                    x={positions[i][0]}
                    y={positions[i][1]}
                    color={eventColor}
                    label={kind(row.event)}
                  />
                ))}
                {graph.detections.map((d, i) => (
                  <Cube
                    key={d.detection_id}
                    x={detectionPositions[i][0]}
                    y={detectionPositions[i][1]}
                    color={alertColor}
                    label={d.title}
                  />
                ))}
                {!graph.events.length && (
                  <text x="345" y="270" className="soc-rel-empty">
                    연결 가능한 이벤트 없음
                  </text>
                )}
                {!graph.detections.length && (
                  <text x="345" y="438" className="soc-rel-empty">
                    표시된 이벤트의 탐지 근거 없음
                  </text>
                )}
              </svg>
              <div className="soc-rel-details">
                <strong>{display(detail.endpoint.host)}</strong>
                <p>
                  수집기 {display(detail.endpoint.collector_id)} · 관찰 이벤트{" "}
                  {graph.totalEvents}건 · 탐지 {graph.totalDetections}건
                </p>
                <h4>
                  표시된 이벤트{" "}
                  <span>
                    {graph.events.length} / {graph.totalEvents}
                  </span>
                </h4>
                {graph.events.length ? (
                  <ul>
                    {graph.events.map(({ batch, event }) => (
                      <li key={`${batch.analysis_id}-${event.event_id}`}>
                        <Button
                          label={`${kind(event)} · ${display(event.event_id)}`}
                          variant="ghost"
                          size="sm"
                          onClick={() =>
                            onEvent(batch.analysis_id, event.event_id)
                          }
                        />
                        <span>
                          발생 {display(event.timestamp)} · 수신{" "}
                          {display(batch.received_at)}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>연결 가능한 이벤트가 없습니다.</p>
                )}
                <h4>
                  표시된 탐지{" "}
                  <span>
                    {graph.detections.length} / {graph.totalDetections}
                  </span>
                </h4>
                {graph.detections.length ? (
                  <ul>
                    {graph.detections.map((d, detectionIndex) => (
                      <li key={d.detection_id}>
                        <Button
                          label={display(d.title)}
                          variant="ghost"
                          size="sm"
                          onClick={() => onDetection(d.detection_id)}
                        />
                        <span>
                          {source(d.source)} ·{" "}
                          {d.status === "approved_for_simulated_response"
                            ? "시뮬레이션 승인"
                            : d.status === "pending_review"
                              ? "검토 필요"
                              : display(d.status)}
                        </span>
                        <span>
                          근거 이벤트{" "}
                          {graph.edges
                            .filter(
                              (edge) => edge.detectionIndex === detectionIndex,
                            )
                            .map((edge) =>
                              display(
                                graph.events[edge.eventIndex].event.event_id,
                              ),
                            )
                            .join(", ")}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>표시된 이벤트에서 확인된 탐지 근거가 없습니다.</p>
                )}
              </div>
            </div>
            {graph.excluded > 0 && (
              <p className="soc-rel-limit">
                식별 범위가 불명확한 이벤트 {graph.excluded}건은 연결하지
                않았습니다.
              </p>
            )}
            <p className="soc-rel-limit">
              가독성을 위해 이벤트와 탐지는 각각 최대 3건만 표시합니다. 더 많은
              이력은 이벤트·탐지 목록에서 확인하세요.
            </p>
          </>
        )}
    </section>
  );
}
