// Guided mode — the same data, explained (§11, ADR-115).
//
// PraHari is built for a SOC operator who already knows what a flow
// record is. Someone who does not opens the Overview and meets
// "Persisted Events / Normalized canonical flows" with no way in.
//
// The rule this layer follows, and the reason it is safe:
//
//   * It NEVER changes a number, a verdict or a refusal. Guided mode
//     adds sentences and defers detail; it does not simplify a claim.
//   * It NEVER hides a warning, a limitation, a refusal reason or a
//     "not measured". Those exist because the honest answer is
//     uncomfortable, and a beginner needs them MORE than an expert,
//     not less. `<Advanced>` is for dense diagnostics only, and
//     `GuidedMode.test.tsx` pins that the capability-limits and
//     refusal panels render in both modes.
//   * The expert's view is unchanged. Turning guided mode off restores
//     exactly what was there before, with every panel expanded.
//
// Default ON. A newcomer does not know the setting exists; an operator
// turns it off once and the choice sticks.

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { ChevronDown, ChevronRight, GraduationCap, Info } from "lucide-react";

const STORAGE_KEY = "prahari.guidedMode";

interface GuidedModeValue {
  guided: boolean;
  setGuided: (on: boolean) => void;
}

const GuidedModeContext = createContext<GuidedModeValue>({
  guided: true,
  setGuided: () => undefined,
});

/**
 * Read the stored preference.
 *
 * Storage can throw (private browsing, blocked site data) and can hold
 * anything, so an unreadable or unrecognised value falls back to the
 * default rather than propagating.
 */
function readStored(): boolean {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw === "on") return true;
    if (raw === "off") return false;
  } catch {
    /* unreadable storage is not an error worth showing anyone */
  }
  return true;
}

export const GuidedModeProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [guided, setGuidedState] = useState<boolean>(readStored);

  const setGuided = useCallback((on: boolean) => {
    setGuidedState(on);
    try {
      window.localStorage.setItem(STORAGE_KEY, on ? "on" : "off");
    } catch {
      /* the preference simply does not persist; the session still works */
    }
  }, []);

  const value = useMemo(() => ({ guided, setGuided }), [guided, setGuided]);

  // Pages that need to react in CSS rather than in JSX read this.
  useEffect(() => {
    document.body.dataset.guided = guided ? "on" : "off";
  }, [guided]);

  return (
    <GuidedModeContext.Provider value={value}>
      {children}
    </GuidedModeContext.Provider>
  );
};

export function useGuidedMode(): GuidedModeValue {
  return useContext(GuidedModeContext);
}

/* ---- The toggle -------------------------------------------------- */

export const GuidedModeToggle: React.FC = () => {
  const { guided, setGuided } = useGuidedMode();
  return (
    <button
      type="button"
      className={`guided-toggle ${guided ? "is-on" : ""}`}
      onClick={() => setGuided(!guided)}
      aria-pressed={guided}
      title={
        guided
          ? "Guided mode is on: plain-language explanations are shown and dense panels start collapsed."
          : "Guided mode is off: every panel is expanded and explanations are hidden."
      }
    >
      <GraduationCap size={15} />
      <span>Guided</span>
      <span className="guided-toggle-state">{guided ? "On" : "Off"}</span>
    </button>
  );
};

/* ---- Plain-language explanation ---------------------------------- */

/**
 * A sentence that says what the thing above it means, in words that do
 * not assume the reader has run a SOC. Rendered only in guided mode.
 *
 * It explains; it never qualifies. Anything that limits what a number
 * means belongs in the page itself, where both modes show it.
 */
export const Explain: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const { guided } = useGuidedMode();
  if (!guided) return null;
  return (
    <p className="explain">
      <Info size={14} className="explain-icon" aria-hidden="true" />
      <span>{children}</span>
    </p>
  );
};

/* ---- Deferred detail --------------------------------------------- */

/**
 * A dense diagnostic panel, collapsed in guided mode.
 *
 * `summary` is what a beginner sees instead, and must be enough to know
 * whether to open it. In expert mode the children render directly with
 * no wrapper chrome, so the page is exactly what it was.
 *
 * Never wrap a warning, a refusal, a limitation or an unavailability in
 * this. A reader who needs guided mode needs those most.
 */
export const Advanced: React.FC<{
  title: string;
  summary?: React.ReactNode;
  children: React.ReactNode;
}> = ({ title, summary, children }) => {
  const { guided } = useGuidedMode();
  const [open, setOpen] = useState(false);

  if (!guided) return <>{children}</>;
  return (
    <div className="advanced">
      <button
        type="button"
        className="advanced-toggle"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
      >
        {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
        <span className="advanced-title">{title}</span>
        {summary !== undefined && !open && (
          <span className="advanced-summary">{summary}</span>
        )}
      </button>
      {open && <div className="advanced-body">{children}</div>}
    </div>
  );
};

/* ---- What to do next --------------------------------------------- */

export interface NextStep {
  label: string;
  detail: string;
  onSelect: () => void;
}

/**
 * The question a newcomer actually has on arrival is "what do I do
 * now?", and no amount of relabelling a stat card answers it.
 *
 * Each step names a real page and says what it is for. Nothing here
 * claims a result — the steps are navigation, not findings.
 */
export const NextSteps: React.FC<{
  heading?: string;
  steps: NextStep[];
}> = ({ heading = "What you can do from here", steps }) => {
  const { guided } = useGuidedMode();
  if (!guided || steps.length === 0) return null;
  return (
    <section className="next-steps" aria-label={heading}>
      <h3 className="next-steps-heading">{heading}</h3>
      <div className="next-steps-grid">
        {steps.map((step) => (
          <button
            key={step.label}
            type="button"
            className="next-step"
            onClick={step.onSelect}
          >
            <span className="next-step-label">{step.label}</span>
            <span className="next-step-detail">{step.detail}</span>
          </button>
        ))}
      </div>
    </section>
  );
};

/* ---- Plain-language value labels ---------------------------------- */

/**
 * A stat card's caption, in one of two registers.
 *
 * `expert` is the wording that was already there and that an operator
 * reads fastest. `plain` says the same thing without the vocabulary.
 * Both describe the SAME number — this is a translation, never a
 * different measurement.
 */
export const Caption: React.FC<{ plain: string; expert: string }> = ({
  plain,
  expert,
}) => {
  const { guided } = useGuidedMode();
  return <>{guided ? plain : expert}</>;
};
