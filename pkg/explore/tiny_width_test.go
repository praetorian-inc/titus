package explore

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// A terminal can be resized to a few columns; every pane and the whole model must still render without panicking (negative strings.Repeat counts).
func TestPanes_TinyTerminalDoesNotPanic(t *testing.T) {
	o := narrowOcc
	o.Path = strings.Repeat("秘密", 15) + "/END.yml"
	m := matchWith(10, o, occWeb)
	m.NamedGroups = map[string][]byte{"秘密token": []byte("秘密秘密秘密")}
	f := &findingRow{RuleName: "r", RuleID: "id", Groups: [][]byte{[]byte("秘密秘密秘密秘密")}, Matches: []*matchRow{m}}
	for w := 0; w <= 12; w++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("details width %d: %v", w, r)
				}
			}()
			dp := newDetailsPane()
			dp.setSize(w, 30)
			dp.setFinding(f)
			_ = dp.View()
			_ = dp.maxOffset()
		}()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("findings width %d: %v", w, r)
				}
			}()
			fp := newFindingsPane([]*findingRow{f})
			fp.setSize(w, 10)
			_ = fp.View()
		}()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("filters width %d: %v", w, r)
				}
			}()
			fl := newFilterPane(buildFacets([]*findingRow{f}))
			fl.setSize(w, 10)
			_ = fl.View()
		}()
		for h := 0; h <= 12; h += 4 {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("model %dx%d: %v", w, h, r)
					}
				}()
				mm := newTestModel([]*findingRow{f})
				nm, _ := mm.Update(tea.WindowSizeMsg{Width: w, Height: h})
				_ = nm.View()
			}()
		}
	}
}
