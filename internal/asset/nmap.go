package asset

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

func itoa(i int) string { return strconv.Itoa(i) }

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames struct {
		Names []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name string `xml:"name,attr"`
			} `xml:"service"`
		} `xml:"port"`
	} `xml:"ports"`
}

func Scan(ctx context.Context, targets string) ([]Asset, error) {
	cmd := exec.CommandContext(ctx, "nmap",
		"-sT", "-T4",
		"--top-ports", "100",
		"--max-retries", "1",
		"--host-timeout", "30s",
		"-oX", "-",
		targets,
	)

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("scan timed out: %w", ctx.Err())
		}
		return nil, fmt.Errorf("nmap failed: %w", err)
	}
	return parse(out)
}

func parse(data []byte) ([]Asset, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}

	now := time.Now().UTC()
	assets := []Asset{}

	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}
		ip := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" {
				ip = a.Addr
				break
			}
		}
		if ip == "" {
			continue
		}
		hostname := ""
		if len(h.Hostnames.Names) > 0 {
			hostname = h.Hostnames.Names[0].Name
		}

		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			assets = append(assets, Asset{
				Host:     ip,
				Hostname: hostname,
				Proto:    p.Protocol,
				Port:     p.PortID,
				Service:  p.Service.Name,
				State:    "open",
				LastSeen: now,
			})
		}
	}
	return assets, nil
}
