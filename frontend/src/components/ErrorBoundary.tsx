import React from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
  /** Shown in the fallback so the user knows which view failed. */
  pageName: string;
  /** Changing this resets the boundary — used to recover on navigation. */
  resetKey?: string;
  children: React.ReactNode;
}

interface State {
  error: Error | null;
  info: React.ErrorInfo | null;
}

/**
 * Contains a render failure to the page that caused it.
 *
 * React 18 unmounts the entire tree when a render error reaches the root,
 * which is why a single bad field reference blanked the whole application
 * and forced a reload. A boundary around the page content keeps the header
 * and navigation mounted, so the user can move to another view and keep
 * working.
 *
 * The boundary resets when `resetKey` changes, so navigating away from a
 * broken page and back re-attempts the render rather than showing a stale
 * failure forever.
 */
export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null, info: null };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // Keep the detail in the console for debugging; the UI shows a summary.
    console.error(`[PraHari] Render error in "${this.props.pageName}":`, error, info);
    this.setState({ info });
  }

  componentDidUpdate(prev: Props) {
    if (this.state.error && prev.resetKey !== this.props.resetKey) {
      this.setState({ error: null, info: null });
    }
  }

  private retry = () => this.setState({ error: null, info: null });

  render() {
    const { error, info } = this.state;
    if (!error) return this.props.children;

    return (
      <div
        className="glass-panel"
        style={{ padding: "2rem", borderLeft: "4px solid var(--accent-rose)" }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.6rem",
            color: "#fca5a5",
            fontWeight: 600,
            fontSize: "1.05rem",
          }}
        >
          <AlertTriangle size={20} />
          The {this.props.pageName} view failed to render
        </div>

        <p
          style={{
            marginTop: "0.9rem",
            fontSize: "0.85rem",
            lineHeight: 1.6,
            color: "var(--text-muted)",
          }}
        >
          This view hit an error while drawing. The rest of the application is
          unaffected — you can switch to another page using the navigation
          above, or retry below.
        </p>

        <div
          style={{
            marginTop: "1rem",
            padding: "0.75rem 0.9rem",
            background: "rgba(0,0,0,0.25)",
            border: "1px solid var(--border-subtle)",
            borderRadius: "6px",
            fontFamily: "monospace",
            fontSize: "0.74rem",
            color: "var(--text-dim)",
            wordBreak: "break-word",
          }}
        >
          {error.name}: {error.message}
        </div>

        {info?.componentStack && (
          <details style={{ marginTop: "0.75rem" }}>
            <summary
              style={{ cursor: "pointer", fontSize: "0.76rem", color: "var(--text-dim)" }}
            >
              Component stack
            </summary>
            <pre
              style={{
                marginTop: "0.5rem",
                fontSize: "0.68rem",
                color: "var(--text-dim)",
                whiteSpace: "pre-wrap",
                maxHeight: "14rem",
                overflow: "auto",
              }}
            >
              {info.componentStack.trim()}
            </pre>
          </details>
        )}

        <button className="btn btn-secondary" onClick={this.retry} style={{ marginTop: "1.25rem" }}>
          <RefreshCw size={14} /> Retry this view
        </button>
      </div>
    );
  }
}
