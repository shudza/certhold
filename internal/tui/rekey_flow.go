package tui

import (
	"bytes"
	"context"
	"errors"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/shudza/certhold/internal/ops"
)

// errPassphraseMismatch is returned by the rotate-passphrase source when the
// two confirmation entries differ; the source re-prompts in place rather than
// surfacing it, so it never reaches the worker on a normal mismatch.
var errPassphraseMismatch = errors.New("passphrases did not match")

// rekeyModal is the guarded confirm for a full-fleet rekey. The operator must
// type the literal word "rekey" (typo-resistant: anything else leaves submit
// inert); the rotate field toggles a fresh at-rest CA passphrase. It is a tiny
// two-field form — confirm text + a boolean toggle — navigated with tab.
type rekeyModal struct {
	confirm textinput.Model
	rotate  bool
	field   int // 0 = confirm text, 1 = rotate toggle
}

func newRekeyModal() rekeyModal {
	ti := textinput.New()
	ti.Prompt = "type rekey to confirm: "
	ti.CharLimit = 16
	ti.Focus()
	return rekeyModal{confirm: ti}
}

func (r rekeyModal) title() string { return "rekey fleet" }

func (r rekeyModal) confirmed() bool { return r.confirm.Value() == "rekey" }

func (r rekeyModal) handle(msg tea.KeyMsg) (modal, modalResult) {
	switch msg.String() {
	case "esc":
		return r, modalClose
	case "enter":
		if r.confirmed() {
			return r, modalSubmit
		}
		return r, modalKeep
	case "tab", "down", "up":
		r.field = (r.field + 1) % 2
		if r.field == 0 {
			r.confirm.Focus()
		} else {
			r.confirm.Blur()
		}
		return r, modalKeep
	case " ":
		if r.field == 1 {
			r.rotate = !r.rotate
			return r, modalKeep
		}
	}
	if r.field == 0 {
		var cmd tea.Cmd
		r.confirm, cmd = r.confirm.Update(msg)
		_ = cmd
	}
	return r, modalKeep
}

func (r rekeyModal) view(int, int) []string {
	rotate := "[ ]"
	if r.rotate {
		rotate = "[x]"
	}
	rotateLine := rotate + " rotate at-rest CA passphrase"
	if r.field == 1 {
		rotateLine = selStyle.Render(rotateLine)
	}
	gate := modalHintStyle.Render("(submit stays inert until you type rekey)")
	if r.confirmed() {
		gate = okStyle.Render("✓ confirmed")
	}
	return []string{
		dimStyle.Render("Rotate the CA and reissue+push certs to every peer."),
		dimStyle.Render("Unreachable peers become stragglers (reported, not fatal)."),
		"",
		r.confirm.View(),
		gate,
		"",
		rotateLine,
		"",
		modalHintStyle.Render("tab switch field · space toggle · enter rekey · esc cancel"),
	}
}

// startRekey opens the rekey confirm modal. Gated by --read-only and only from
// a non-modal state; a missing action seam (read-only) makes it a no-op.
func (m Model) startRekey() (tea.Model, tea.Cmd) {
	if !m.mutationsEnabled() || (m.view != viewPeers && m.view != viewGroups) {
		return m, nil
	}
	m.pushModal(newRekeyModal())
	return m, nil
}

// submitRekey is reached when the operator confirmed the word and pressed
// enter. With rotate off it launches the rekey directly (CAUnlock may still
// prompt, like every other action). With rotate on it wires a NewPassphrase
// source that prompts twice through the same passSession channel and re-prompts
// on mismatch — all on the worker goroutine, so the event loop never blocks.
func (m Model) submitRekey(r rekeyModal) (tea.Model, tea.Cmd) {
	hostname := m.action.Hostname
	rotate := r.rotate
	newPass := m.rotatePassphraseSource()
	run := func(ctx context.Context, deps ops.Deps) error {
		return ops.Rekey(ctx, deps, ops.RekeyOptions{
			Hostname:         hostname,
			RotatePassphrase: rotate,
			NewPassphrase:    newPass,
		})
	}
	return m.startAction("rekey fleet", run)
}

// rotatePassphraseSource returns a NewPassphrase func for ops.Rekey. It runs on
// the worker goroutine: it raises a "new passphrase" prompt and a "confirm"
// prompt over the same passSession the CAUnlock bridge uses, and loops on
// mismatch so the operator re-enters both. A canceled entry aborts the rekey
// (errPassphraseCanceled propagates out of ops.Rekey). The bytes never touch
// the Model; only the textinput inside the modal holds them transiently.
func (m Model) rotatePassphraseSource() func() ([]byte, error) {
	s := m.pass
	return func() ([]byte, error) {
		note := ""
		for {
			first, err := s.promptErr("New CA passphrase", "New CA passphrase: ", note)
			if err != nil {
				return nil, err
			}
			second, err := s.promptErr("Confirm passphrase", "Confirm new CA passphrase: ", "")
			if err != nil {
				zeroBytesTUI(first)
				return nil, err
			}
			if bytes.Equal(first, second) {
				zeroBytesTUI(second)
				return first, nil
			}
			zeroBytesTUI(first)
			zeroBytesTUI(second)
			note = errPassphraseMismatch.Error() + " — try again"
		}
	}
}

func zeroBytesTUI(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
