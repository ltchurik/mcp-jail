package proxy

import (
	"encoding/json"
	"time"

	"github.com/ltchurik/mcp-jail/internal/audit"
	"github.com/ltchurik/mcp-jail/internal/jsonrpc"
	"github.com/ltchurik/mcp-jail/internal/lock"
)

// notifyPoll is the default interval at which a jail with a pending change
// looks at the lock for an approve made elsewhere (mcp-jail approve, the
// dashboard, a terminal review in another shell).
const notifyPoll = time.Second

// watch marks section k as pending: hash is what the lock records for it
// right now ("" when nothing), so an approve shows up as a different hash.
func (p *Proxy) watch(k lock.Kind, hash string) {
	p.lmu.Lock()
	st := p.sections[k]
	st.watching, st.watchHash = true, hash
	p.lmu.Unlock()
}

// listChanged is the notification that tells the client to list kind k
// again; resource templates are covered by the resources one.
func listChanged(k lock.Kind) string {
	switch k {
	case lock.Prompts:
		return "notifications/prompts/list_changed"
	case lock.Resources, lock.ResourceTemplates:
		return "notifications/resources/list_changed"
	}
	return "notifications/tools/list_changed"
}

// watchApprovals polls the lock while any section has a change pending and,
// once a section's recorded hash differs from what it was when the change
// was caught, tells the client to list again. The next list goes through
// the lock as usual: an approved list passes, a partial approve holds what
// is still pending. One notification per approve; the watch is re-armed by
// the next mismatch.
func (p *Proxy) watchApprovals(stop <-chan struct{}) {
	every := p.NotifyPoll
	if every <= 0 {
		every = notifyPoll
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		p.lmu.Lock()
		var kinds []lock.Kind
		for _, k := range lock.Kinds {
			if p.sections[k].watching {
				kinds = append(kinds, k)
			}
		}
		p.lmu.Unlock()
		if len(kinds) == 0 {
			continue
		}
		f, err := lock.Load(p.Policy.Name)
		if err != nil {
			continue // unreadable right now; the next mismatch will say so
		}
		for _, k := range kinds {
			now := ""
			if sec := f.Section(k); sec != nil {
				now = sec.Hash
			}
			p.lmu.Lock()
			st := p.sections[k]
			fire := st.watching && now != st.watchHash
			if fire {
				st.watching = false
			}
			p.lmu.Unlock()
			if !fire {
				continue
			}
			method := listChanged(k)
			p.Audit.Log(audit.Event{Kind: "lock", Decision: "notified", Reason: string(k) + " approved elsewhere; client told to list again (" + method + ")"})
			p.Logf("lock: %s approved; telling the client to list again", k)
			b, _ := json.Marshal(jsonrpc.Message{JSONRPC: "2.0", Method: method})
			p.toClient(b)
		}
	}
}
