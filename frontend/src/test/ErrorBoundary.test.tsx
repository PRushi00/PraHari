import React from "react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ErrorBoundary } from "../components/ErrorBoundary";

/**
 * Regression tests for the blank-page failure.
 *
 * The Feasibility view threw `TypeError: Cannot read properties of
 * undefined (reading 'toFixed')` during render. With no boundary, React 18
 * unmounted the whole tree, so the entire application went blank and only a
 * page reload recovered it.
 */

const Boom: React.FC<{ message?: string }> = ({ message = "kaboom" }) => {
  throw new TypeError(message);
};

const Fine: React.FC = () => <div>page content</div>;

describe("ErrorBoundary", () => {
  beforeEach(() => {
    // React logs caught render errors; keep the test output readable.
    vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders children normally when nothing throws", () => {
    render(
      <ErrorBoundary pageName="Feasibility">
        <Fine />
      </ErrorBoundary>
    );
    expect(screen.getByText("page content")).toBeInTheDocument();
  });

  it("contains a render error instead of unmounting the tree", () => {
    render(
      <div>
        <nav>navigation stays mounted</nav>
        <ErrorBoundary pageName="Feasibility">
          <Boom />
        </ErrorBoundary>
      </div>
    );

    // The surrounding shell survives — this is the whole point.
    expect(screen.getByText("navigation stays mounted")).toBeInTheDocument();
    expect(
      screen.getByText(/The Feasibility view failed to render/i)
    ).toBeInTheDocument();
  });

  it("names the failing page and surfaces the error message", () => {
    render(
      <ErrorBoundary pageName="Threat Forecasting">
        <Boom message="Cannot read properties of undefined (reading 'toFixed')" />
      </ErrorBoundary>
    );
    expect(screen.getByText(/Threat Forecasting view failed/i)).toBeInTheDocument();
    expect(screen.getByText(/reading 'toFixed'/)).toBeInTheDocument();
  });

  it("tells the user the rest of the application still works", () => {
    render(
      <ErrorBoundary pageName="Feasibility">
        <Boom />
      </ErrorBoundary>
    );
    expect(
      screen.getByText(/rest of the application is\s+unaffected/i)
    ).toBeInTheDocument();
  });

  it("recovers when the user retries", () => {
    let shouldThrow = true;
    const Flaky: React.FC = () => {
      if (shouldThrow) throw new Error("transient");
      return <div>recovered content</div>;
    };

    render(
      <ErrorBoundary pageName="Analytics">
        <Flaky />
      </ErrorBoundary>
    );
    expect(screen.getByText(/Analytics view failed/i)).toBeInTheDocument();

    shouldThrow = false;
    fireEvent.click(screen.getByRole("button", { name: /Retry this view/i }));
    expect(screen.getByText("recovered content")).toBeInTheDocument();
  });

  it("resets when the user navigates to a different page", () => {
    let shouldThrow = true;
    const Flaky: React.FC = () => {
      if (shouldThrow) throw new Error("transient");
      return <div>other page</div>;
    };

    const { rerender } = render(
      <ErrorBoundary pageName="Feasibility" resetKey="research">
        <Flaky />
      </ErrorBoundary>
    );
    expect(screen.getByText(/Feasibility view failed/i)).toBeInTheDocument();

    // Navigating away must not leave the app stuck on a stale failure.
    shouldThrow = false;
    rerender(
      <ErrorBoundary pageName="Analytics" resetKey="analysis">
        <Flaky />
      </ErrorBoundary>
    );
    expect(screen.getByText("other page")).toBeInTheDocument();
  });
});
