import React from "react";
import { createRoot } from "react-dom/client";
import { Theme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral/built";
import "@astryxdesign/core/reset.css";
import "@astryxdesign/core/astryx.css";
import "@astryxdesign/theme-neutral/theme.css";
import "./dashboard.css";
import App from "./App.jsx";

const legacyPaths = {
  "#analysis": "/console/events",
  "#result-section": "/console/detections",
  "#history": "/console/history",
  "#overview": "/console",
};
const legacyTarget =
  window.location.pathname === "/" && legacyPaths[window.location.hash];
if (legacyTarget) {
  window.location.replace(legacyTarget);
} else {
  createRoot(document.getElementById("root")).render(
    <Theme theme={neutralTheme} mode="dark">
      <App />
    </Theme>,
  );
}
