package gateway

import (
	"encoding/json"
	"time"

	"openclaw/guard/overseer/internal/capability"
	"openclaw/guard/overseer/internal/inspect"
	"openclaw/guard/overseer/internal/session"
)

// violationsFrom turns one inspection into the rows that record it.
//
// One row per signal, because violation_source is a single value and an
// inspector can report findings from more than one source. One row per failed
// inspector, so a later reader can tell "this prompt had no semantic verdict
// because the gate was down" from "because it was clean" — a distinction that
// decides whether a corpus row is usable at all.
//
// Clean verdicts are recorded only while capturing. A false-positive rate
// cannot be computed from positives alone, so the negatives have to exist; but
// writing a row per inspector per request forever is a permanent cost for a
// bounded exercise.
func violationsFrom(
	outcome inspect.Outcome,
	redacted inspect.Redacted,
	decision capability.Decision,
	storedTier capability.Tier,
	enforced bool,
	capture bool,
) []session.Violation {
	var out []session.Violation

	base := func(src capability.Source, meta map[string]any) session.Violation {
		v := session.Violation{
			Direction:      session.Inbound,
			Source:         src,
			ContentSHA256:  redacted.SHA256,
			ContentPreview: redacted.Preview,
		}
		if capture {
			v.RawContent = redacted.Raw
			v.RawContentExpiresAt = redacted.ExpiresAt
		}
		// What WOULD have happened, when nothing did. The applied_downgrade
		// columns stay NULL on the log-only path, so without this the
		// counterfactual is lost and shadow mode records nothing useful.
		meta["proposed_from"] = storedTier.String()
		meta["proposed_to"] = decision.To.String()
		meta["enforced"] = enforced
		if b, err := json.Marshal(meta); err == nil {
			v.Metadata = b
		}
		return v
	}

	for _, res := range outcome.Results {
		common := func() map[string]any {
			return map[string]any{
				"inspector":   res.Inspector,
				"mode":        res.Mode.String(),
				"duration_ms": res.Duration.Seconds() * 1000,
			}
		}

		switch {
		case res.Err != nil:
			m := common()
			m["error"] = res.Err.Error()
			m["timed_out"] = res.TimedOut
			out = append(out, base(capability.Source(res.Inspector), m))

		case len(res.Signals) > 0:
			for _, sig := range res.Signals {
				m := common()
				m["code"] = sig.Code
				m["weight"] = sig.Weight
				m["confidence"] = sig.Confidence.String()
				v := base(sig.Source, m)
				v.LlamaGuardCode = llamaGuardCode(sig)
				out = append(out, v)
			}

		case capture:
			m := common()
			m["clean"] = true
			out = append(out, base(capability.Source(res.Inspector), m))
		}
	}
	return out
}

// llamaGuardCode fills the denormalised taxonomy column, which only applies to
// the one detector that has a taxonomy. Everything else carries its code in
// metadata, which is the uniform path.
func llamaGuardCode(sig capability.Signal) string {
	if sig.Source == capability.SourceLlamaGuard {
		return sig.Code
	}
	return ""
}

// redactFor builds the durable record of the inspected content.
func redactFor(content string, capture bool, retention time.Duration) inspect.Redacted {
	return inspect.Redact(content, capture, retention, time.Now())
}
