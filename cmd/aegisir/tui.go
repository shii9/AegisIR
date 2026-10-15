package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/shii9/AegisIR/internal/collector"
	"strings"
	"time"
)

func cell(v string, max int) string {
	r := []rune(v)
	if len(r) > max {
		if max > 2 {
			v = string(r[:max-1]) + "…"
		} else {
			v = string(r[:max])
		}
	}
	return fmt.Sprintf("%-*s", max, v)
}

func tuiView(args []string) error {
	if len(args) == 0 {
		return nil
	}
	cmd := args[0]
	if cmd == "demo" {
		data, err := call(map[string]any{"op": "demo"})
		if err != nil {
			return err
		}
		var d struct {
			CaseID    string `json:"case_id"`
			Total     int    `json:"total_findings"`
			Synthetic bool   `json:"synthetic"`
		}
		if err := json.Unmarshal(data, &d); err != nil {
			return err
		}
		fmt.Printf("\n  Synthetic case created: %s\n  Review indicators: %d\n  No live actions permitted in synthetic cases.\n", d.CaseID, d.Total)
		fmt.Printf("  Next: aegisir advanced findings %s\n", d.CaseID)
		return nil
	}
	if cmd == "scan" && len(args) >= 2 {
		module := "all"
		if len(args) >= 4 && args[2] == "--module" && args[3] != "" {
			module = args[3]
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
		defer cancel()
		results, err := collector.Collect(ctx, module)
		if err != nil {
			return err
		}
		data, err := call(map[string]any{"op": "scan", "case_id": args[1], "modules": results})
		if err != nil {
			return err
		}
		var v struct {
			Total   int `json:"total_findings"`
			Modules []struct {
				Module   string `json:"module"`
				Status   string `json:"status"`
				Items    int    `json:"items"`
				Findings int    `json:"findings"`
			} `json:"modules"`
		}
		if err := json.Unmarshal(data, &v); err != nil {
			return err
		}
		fmt.Printf("\n  %-13s %-11s %-9s %-8s\n", "MODULE", "STATUS", "ITEMS", "FINDINGS")
		fmt.Println("  " + strings.Repeat("─", 55))
		for _, x := range v.Modules {
			fmt.Printf("  %-13s %-11s %-9d %-8d\n", x.Module, x.Status, x.Items, x.Findings)
		}
		fmt.Printf("\n  Total heuristic findings: %d (not confirmed compromise)\n", v.Total)
		fmt.Println("  Next: inspect findings, corroborate and decide with reason")
		return nil
	}
	if cmd == "cases" {
		data, err := call(map[string]any{"op": "cases"})
		if err != nil {
			return err
		}
		var cs []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Phase    string `json:"phase"`
			Status   string `json:"status"`
			Title    string `json:"title"`
		}
		if err := json.Unmarshal(data, &cs); err != nil {
			return err
		}
		fmt.Printf("\n  %s %s %s %s %s\n", cell("CASE ID", 15), cell("SEVERITY", 9), cell("PHASE", 15), cell("STATUS", 9), "TITLE")
		fmt.Println("  " + strings.Repeat("─", 85))
		for _, c := range cs {
			fmt.Printf("  %s %s %s %s %s\n", cell(c.ID, 15), cell(c.Severity, 9), cell(c.Phase, 15), cell(c.Status, 9), cell(c.Title, 45))
		}
		if len(cs) == 0 {
			fmt.Println("  No cases yet.")
		}
		return nil
	}
	if cmd == "findings" && len(args) >= 2 {
		data, err := call(request("findings", args[1]))
		if err != nil {
			return err
		}
		var fs []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Module   string `json:"module"`
			Rule     string `json:"rule"`
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal(data, &fs); err != nil {
			return err
		}
		fmt.Printf("\n  %s %s %s %s %s\n", cell("FINDING", 15), cell("SEVERITY", 9), cell("MODULE", 12), cell("DECISION", 11), "RULE")
		fmt.Println("  " + strings.Repeat("─", 85))
		for _, f := range fs {
			fmt.Printf("  %s %s %s %s %s\n", cell(f.ID, 15), cell(f.Severity, 9), cell(f.Module, 12), cell(f.Decision, 11), cell(f.Rule, 32))
		}
		if len(fs) == 0 {
			fmt.Println("  No heuristic findings — this does NOT prove the host is clean.")
		}
		return nil
	}
	if cmd == "show" && len(args) >= 2 {
		data, err := call(request("show", args[1]))
		if err != nil {
			return err
		}
		var v struct {
			Case struct {
				ID       string `json:"id"`
				Title    string `json:"title"`
				Asset    string `json:"asset"`
				Severity string `json:"severity"`
				Phase    string `json:"phase"`
				Status   string `json:"status"`
			} `json:"case"`
			Summary struct {
				Scans    int `json:"scans"`
				Findings int `json:"findings"`
			} `json:"summary"`
			Three map[string]struct {
				Status string `json:"status"`
			} `json:"three_questions"`
		}
		if err := json.Unmarshal(data, &v); err != nil {
			return err
		}
		fmt.Printf("\n  CASE %s  |  %s  |  %s\n  %s (%s)\n  Current phase: %s\n  Evidence scans: %d | Suspicious hypotheses: %d\n", v.Case.ID, v.Case.Severity, v.Case.Status, v.Case.Title, v.Case.Asset, v.Case.Phase, v.Summary.Scans, v.Summary.Findings)
		fmt.Println("\n  Three IR questions (not validated verdicts):")
		for _, k := range []string{"active_malware", "suspicious_communications", "persistence"} {
			fmt.Printf("    %-27s %s\n", strings.ReplaceAll(k, "_", " "), v.Three[k].Status)
		}
		return nil
	}
	if cmd == "checklist" && len(args) >= 2 {
		data, err := call(request("checklist", args[1]))
		if err != nil {
			return err
		}
		var v struct {
			Checklist []struct {
				Phase string `json:"phase"`
				Item  string `json:"item"`
				Done  int    `json:"done"`
			} `json:"checklist"`
		}
		if err := json.Unmarshal(data, &v); err != nil {
			return err
		}
		phase := ""
		for _, x := range v.Checklist {
			if x.Phase != phase {
				phase = x.Phase
				fmt.Printf("\n  %s\n", strings.ToUpper(phase))
			}
			c := " "
			if x.Done != 0 {
				c = "x"
			}
			fmt.Printf("   [%s] %s\n", c, strings.ReplaceAll(x.Item, "_", " "))
		}
		fmt.Println("\n  Complete items via: aegisir advanced check CASE --phase P --item KEY --note 'Evidence...'")
		return nil
	}
	return advancedRun(args)
}
