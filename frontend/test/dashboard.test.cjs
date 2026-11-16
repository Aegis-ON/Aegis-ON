"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { JSDOM, VirtualConsole } = require("jsdom");
const fs = require("node:fs");
const path = require("node:path");
const bundle = fs.readFileSync(
  path.join(__dirname, "../../static/astryx/app.js"),
  "utf8",
);
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(fn) {
  for (let i = 0; i < 80; i++) {
    if (fn()) return;
    await wait(25);
  }
  throw new Error("timed out waiting for UI");
}
function text(node) {
  return node.textContent.replace(/\s+/g, " ").trim();
}
function button(doc, needle, parent = doc) {
  return [...parent.querySelectorAll("button")].find((b) =>
    text(b).includes(needle),
  );
}
function syntheticHistory() {
  return {
    analyses: [
      {
        analysis_id: "batch-1",
        analyzed_at: "2026-11-16T11:00:00Z",
        received_at: "2026-11-16T11:01:00Z",
        source_events: [
          {
            event_id: "evt-1",
            sysmon_event_id: 3,
            host: "lab-host",
            timestamp: "2026-11-16T11:00:00Z",
            log_source: "sysmon",
            collector_id: "collector-test",
            endpoint_group: "g",
          },
        ],
        detection_ids: ["det-1"],
      },
    ],
    detections: [
      {
        detection_id: "det-1",
        score: 75,
        title: "synthetic fanout",
        technique: "T1595",
        source: "correlation",
        status: "pending_review",
        host: "lab-host",
        event_ids: ["evt-1"],
        evidence: ["3 destinations"],
      },
    ],
  };
}
function mount(route, handler, options = {}) {
  const errors = [];
  const ticks = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push(e.message));
  const dom = new JSDOM('<!doctype html><div id="root"></div>', {
    url: `http://localhost${route}`,
    runScripts: "dangerously",
    pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(w) {
      w.CSS = { supports: () => false, escape: (s) => String(s) };
      if (options.fastTimeout) {
        const original = w.setTimeout.bind(w);
        w.setTimeout = (fn, ms, ...args) =>
          original(fn, ms === 15000 ? 40 : ms, ...args);
      }
      w.setInterval = (fn) => {
        ticks.push(fn);
        return ticks.length;
      };
      w.clearInterval = () => {};
      w.fetch = handler;
      w.matchMedia = () => ({
        matches: false,
        addEventListener() {},
        removeEventListener() {},
        addListener() {},
        removeListener() {},
      });
      w.ResizeObserver = class {
        observe() {}
        unobserve() {}
        disconnect() {}
      };
      w.HTMLElement.prototype.scrollIntoView = function () {};
      w.HTMLDialogElement.prototype.showModal = function () {
        this.setAttribute("open", "");
      };
      w.HTMLDialogElement.prototype.close = function () {
        this.removeAttribute("open");
      };
      w.console.error = (...x) => errors.push(x.join(" "));
    },
  });
  dom.window.eval(bundle);
  return { dom, doc: dom.window.document, errors, ticks };
}
const ok = (data) => ({ ok: true, status: 200, json: async () => data });
const failed = (status) => ({ ok: false, status, json: async () => ({}) });
function baseHandler(data, override) {
  return async (url, opts = {}) => {
    if (override) {
      const result = await override(url, opts);
      if (result) return result;
    }
    const values = {
      "/api/v1/session": { analyst: "analyst", csrf_token: "csrf-test" },
      "/api/v1/history": data,
      "/api/v1/endpoints": { endpoints: [] },
      "/api/v1/collectors": { collectors: [] },
      "/api/v1/pii/status": { state: "disabled" },
      "/api/v1/attack-model/status": { state: "disabled" },
    };
    return Object.hasOwn(values, url) ? ok(values[url]) : failed(404);
  };
}

test("detection, related evidence, simulated approval and CSRF", async () => {
  const data = syntheticHistory();
  let request;
  const { dom, doc, errors } = mount(
    "/console/detections",
    baseHandler(data, (url, opts) => {
      if (url === "/api/v1/detections/det-1/approval") {
        request = opts;
        data.detections[0].status = "approved_for_simulated_response";
        data.detections[0].approval = {
          analyst: "analyst",
          approved_at: "2026-11-16",
          rationale: "",
        };
        return ok({ simulation_only: true });
      }
    }),
  );
  try {
    await until(() => button(doc, "synthetic fanout"));
    assert.match(text(doc.body), /상관분석.*검토 필요/);
    button(doc, "synthetic fanout").click();
    await until(() => doc.querySelector('[aria-label="상세 정보"]'));
    const detail = doc.querySelector('[aria-label="상세 정보"]');
    assert.match(text(detail), /3 destinations/);
    assert.match(text(detail), /collector-test/);
    assert.match(text(detail), /실제 차단이 아닌 시뮬레이션/);
    button(doc, "시뮬레이션 승인", detail).click();
    await until(() => doc.querySelector("dialog[open]"));
    button(doc, "시뮬레이션 승인", doc.querySelector("dialog[open]")).click();
    await until(() => request);
    assert.equal(request.headers["X-CSRF-Token"], "csrf-test");
    assert.equal(JSON.parse(request.body).analyst, "analyst");
    await until(() => text(doc.body).includes("시뮬레이션 승인"));
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});

test("partial API failure does not replace unknown host count with a successful empty result", async () => {
  const { dom, doc, errors } = mount(
    "/",
    baseHandler(syntheticHistory(), (url) =>
      url === "/api/v1/endpoints" ? failed(503) : undefined,
    ),
  );
  try {
    await until(() =>
      text(doc.body).includes("호스트 정보를 불러오지 못했습니다"),
    );
    assert.match(text(doc.body), /synthetic fanout/);
    assert.doesNotMatch(text(doc.body), /관찰된 호스트 정보가 없습니다/);
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});

test("refresh preserves the selected detection and escapes text", async () => {
  const data = syntheticHistory();
  data.detections[0].title = "<img src=x onerror=alert(1)>";
  const { dom, doc, errors } = mount("/console/detections", baseHandler(data));
  try {
    await until(() => button(doc, "<img src=x"));
    button(doc, "<img src=x").click();
    await until(() => doc.querySelector('[aria-label="상세 정보"]'));
    assert.equal(doc.querySelectorAll('img[src="x"]').length, 0);
    data.detections.unshift({
      detection_id: "det-new",
      score: 44,
      title: "new detection",
      technique: "T0",
      status: "pending_review",
      source: "rule",
      event_ids: [],
    });
    button(doc, "새로고침").click();
    await until(() => button(doc, "new detection"));
    assert.match(
      text(doc.querySelector('[aria-label="상세 정보"]')),
      /<img src=x/,
    );
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});

function setInput(win, input, value) {
  const setter = Object.getOwnPropertyDescriptor(
    win.HTMLInputElement.prototype,
    "value",
  ).set;
  setter.call(input, value);
  input.dispatchEvent(new win.Event("input", { bubbles: true }));
}

test("failed login clears the password and does not disclose credentials", async () => {
  let submitted;
  const { dom, doc, errors } = mount("/login", async (url, opts) => {
    submitted = JSON.parse(opts.body);
    return failed(401);
  });
  try {
    await until(() => doc.querySelector('input[name="username"]'));
    const user = doc.querySelector('input[name="username"]'),
      pass = doc.querySelector('input[name="password"]');
    setInput(dom.window, user, "test-analyst");
    setInput(dom.window, pass, "synthetic-secret");
    doc
      .querySelector("form")
      .dispatchEvent(
        new dom.window.Event("submit", { bubbles: true, cancelable: true }),
      );
    await until(() => text(doc.body).includes("올바르지 않습니다"));
    assert.equal(submitted.password, "synthetic-secret");
    assert.equal(pass.value, "");
    assert.doesNotMatch(text(doc.body), /synthetic-secret/);
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});

test("collector credential remains out of DOM and copy failure is reported", async () => {
  let registered;
  const { dom, doc, errors } = mount(
    "/console/endpoints",
    baseHandler(syntheticHistory(), (url, opts) => {
      if (url === "/api/v1/collectors/register") {
        registered = JSON.parse(opts.body);
        return ok({
          collector_id: registered.collector_id,
          credential: "synthetic-credential-value",
        });
      }
    }),
  );
  try {
    await until(() => doc.querySelector("input[placeholder]"));
    const input = doc.querySelector("input[placeholder]");
    setInput(dom.window, input, "collector-a");
    input.form.dispatchEvent(
      new dom.window.Event("submit", { bubbles: true, cancelable: true }),
    );
    await until(() => button(doc, "인증 정보 복사"));
    assert.equal(registered.collector_id, "collector-a");
    assert.doesNotMatch(text(doc.body), /synthetic-credential-value/);
    button(doc, "인증 정보 복사").click();
    await until(() => text(doc.body).includes("복사하지 못했습니다"));
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});

test("inserting new detection preserves the focused row target", async () => {
  const data = syntheticHistory();
  const { dom, doc, errors } = mount("/console/detections", baseHandler(data));
  try {
    await until(() => button(doc, "synthetic fanout"));
    const original = button(doc, "synthetic fanout");
    original.focus();
    assert.equal(doc.activeElement, original);
    data.detections.unshift({
      detection_id: "new-id",
      title: "new row",
      score: 30,
      source: "rule",
      status: "pending_review",
    });
    button(doc, "새로고침").click();
    await until(() => button(doc, "new row"));
    assert.equal(doc.activeElement, original);
    assert.match(text(doc.activeElement), /synthetic fanout/);
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});

test("initial session failure retries and then loads data", async () => {
  let attempt = 0;
  const { dom, doc, errors, ticks } = mount(
    "/console/events",
    baseHandler(syntheticHistory(), (url) => {
      if (url === "/api/v1/session" && ++attempt === 1) return failed(503);
    }),
  );
  try {
    await until(() => text(doc.body).includes("세션 확인 실패"));
    assert.ok(ticks.length);
    assert.equal(button(doc, "새로고침").getAttribute("aria-disabled"), "true");
    ticks[0]();
    await until(() => text(doc.body).includes("evt-1"));
    assert.ok(attempt >= 2);
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});

test("history outage preserves displayed data and shows recovery", async () => {
  let offline = false;
  const { dom, doc, errors } = mount(
    "/console/events",
    baseHandler(syntheticHistory(), (url) =>
      url === "/api/v1/history" && offline ? failed(503) : undefined,
    ),
  );
  try {
    await until(() => text(doc.body).includes("evt-1"));
    offline = true;
    button(doc, "새로고침").click();
    await until(() => text(doc.body).includes("화면 연결 오류"));
    assert.match(text(doc.body), /evt-1/);
    offline = false;
    button(doc, "새로고침").click();
    await until(() => text(doc.body).includes("화면 연결 복구됨"));
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});

test("slow history response is not starved by repeated refresh ticks", async () => {
  let release,
    calls = 0;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const { dom, doc, errors, ticks } = mount(
    "/console/events",
    baseHandler(syntheticHistory(), async (url) => {
      if (url === "/api/v1/history") {
        calls++;
        await gate;
      }
    }),
  );
  try {
    await until(() => calls === 1);
    for (let i = 0; i < 3; i++) for (const tick of ticks) tick();
    await wait(40);
    assert.equal(calls, 1);
    release();
    await until(() => text(doc.body).includes("evt-1"));
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    release();
    dom.window.close();
  }
});

test("timed out history request releases the refresh lock and recovers", async () => {
  let attempts = 0;
  const { dom, doc, errors } = mount(
    "/console/events",
    baseHandler(syntheticHistory(), (url, opts) => {
      if (url === "/api/v1/history" && ++attempts === 1)
        return new Promise((resolve, reject) =>
          opts.signal.addEventListener("abort", () => {
            const e = new Error("aborted");
            e.name = "AbortError";
            reject(e);
          }),
        );
    }),
    { fastTimeout: true },
  );
  try {
    await until(() => text(doc.body).includes("시간이 초과"));
    button(doc, "새로고침").click();
    await until(() => text(doc.body).includes("evt-1"));
    assert.equal(attempts, 2);
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});

test("isometric observations come only from the endpoints API and link to their own details", async () => {
  const observations = [
    {
      endpoint_id: "host-a",
      host: "alpha-lab",
      collector_id: "collector-a",
      event_count: 3,
      detection_count: 1,
      highest_score: 78,
    },
    {
      endpoint_id: "host-b",
      host: "beta-lab",
      collector_id: "collector-b",
      event_count: 2,
      detection_count: 0,
      highest_score: null,
    },
  ];
  const { dom, doc, errors } = mount(
    "/",
    baseHandler(syntheticHistory(), (url) =>
      url === "/api/v1/endpoints" ? ok({ endpoints: observations }) : undefined,
    ),
  );
  try {
    await until(() => doc.querySelectorAll(".soc-asset-node").length === 2);
    const nodes = [...doc.querySelectorAll(".soc-asset-node")];
    assert.equal(
      nodes[0].querySelector("a").getAttribute("href"),
      "/console/endpoints/host-a",
    );
    assert.equal(
      nodes[1].querySelector("a").getAttribute("href"),
      "/console/endpoints/host-b",
    );
    assert.match(
      nodes[0].querySelector("a").getAttribute("aria-label"),
      /alpha-lab.*탐지 1건/,
    );
    assert.ok(nodes[0].classList.contains("high"));
    assert.ok(nodes[1].classList.contains("neutral"));
    assert.match(text(doc.body), /배치는 이해를 돕는 표현/);
    assert.match(
      text(doc.body),
      /실제 장치의 연결 관계나 온라인 상태를 의미하지 않습니다/,
    );
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});

test("isometric board shows no synthetic host when the API returns no observations", async () => {
  const { dom, doc, errors } = mount("/", baseHandler(syntheticHistory()));
  try {
    await until(() => text(doc.body).includes("관찰된 호스트 정보가 없습니다"));
    assert.equal(doc.querySelectorAll(".soc-asset-node").length, 0);
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});

test("the asset board limits rendered observations and identifies the total", async () => {
  const observations = Array.from({ length: 8 }, (_, i) => ({
    endpoint_id: `host-${i}`,
    host: `sample-${i}`,
    collector_id: `collector-${i}`,
    event_count: 1,
    detection_count: 0,
    highest_score: null,
  }));
  const { dom, doc, errors } = mount(
    "/",
    baseHandler(syntheticHistory(), (url) =>
      url === "/api/v1/endpoints" ? ok({ endpoints: observations }) : undefined,
    ),
  );
  try {
    await until(() => doc.querySelectorAll(".soc-asset-node").length === 6);
    assert.match(
      text(doc.querySelector(".soc-asset-list-heading")),
      /표시 6 \/ 8/,
    );
    assert.ok(
      [...doc.querySelectorAll(".soc-asset-list a")].some(
        (a) => a.getAttribute("href") === "/console/endpoints",
      ),
    );
    assert.equal(errors.length, 0, errors.join("\n"));
  } finally {
    dom.window.close();
  }
});
