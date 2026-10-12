import "@testing-library/jest-dom/vitest";
import React from "react";
import { vi } from "vitest";

// jsdom has no canvas, so ECharts throws while painting. The charts are not
// under test here — these suites assert page/navigation behaviour — so the
// renderer is stubbed to keep real failures visible instead of buried in
// canvas noise.
vi.mock("echarts-for-react", () => ({
  default: () => React.createElement("div", { "data-testid": "echarts-stub" }),
}));
