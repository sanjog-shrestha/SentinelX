package asset

import (
	"fmt"
	"time"
)

func Diff(previous, current []Asset, at time.Time) []Change {
	prevByKey := map[string]Asset{}
	prevHosts := map[string]bool{}
	for _, a := range previous {
		prevByKey[a.Key()] = a
		prevHosts[a.Host] = true
	}

	curByKey := map[string]Asset{}
	curHosts := map[string]bool{}
	for _, a := range current {
		curByKey[a.Key()] = a
		curHosts[a.Host] = true
	}

	changes := []Change{}
	newHosts := map[string]bool{}

	for host := range curHosts {
		if !prevHosts[host] {
			newHosts[host] = true
			ports := 0
			name := ""
			for _, a := range current {
				if a.Host == host {
					ports++
					if name == "" {
						name = a.Hostname
					}
				}
			}
			changes = append(changes, Change{
				Kind:       KindNewHost,
				Host:       host,
				Detail:     fmt.Sprintf("new host %s (%s) with %d open port(s)", host, orUnknown(name), ports),
				DetectedAt: at,
			})
		}
	}

	// New or changed ports on hosts we already knew about.
	for key, cur := range curByKey {
		if newHosts[cur.Host] {
			continue // already reported as a new host
		}
		prev, existed := prevByKey[key]
		if !existed {
			changes = append(changes, Change{
				Kind: KindNewPort,
				Host: cur.Host, Proto: cur.Proto, Port: cur.Port,
				Detail:     fmt.Sprintf("port %d/%s opened on %s (service %s)", cur.Port, cur.Proto, cur.Host, orUnknown(cur.Service)),
				DetectedAt: at,
			})
			continue
		}
		if prev.Service != cur.Service && cur.Service != "" {
			changes = append(changes, Change{
				Kind: KindService,
				Host: cur.Host, Proto: cur.Proto, Port: cur.Port,
				Detail:     fmt.Sprintf("service on %s:%d changed from %s to %s", cur.Host, cur.Port, orUnknown(prev.Service), cur.Service),
				DetectedAt: at,
			})
		}
	}

	// Ports that disappeared.
	for key, prev := range prevByKey {
		if _, still := curByKey[key]; !still {
			changes = append(changes, Change{
				Kind: KindPortClosed,
				Host: prev.Host, Proto: prev.Proto, Port: prev.Port,
				Detail:     fmt.Sprintf("port %d/%s closed on %s", prev.Port, prev.Proto, prev.Host),
				DetectedAt: at,
			})
		}
	}
	return changes
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
