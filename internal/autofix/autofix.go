package autofix

import (
	"fmt"
	"os"
	"strings"

	"github.com/firfircelik/oteldoctor/internal/model"
	"gopkg.in/yaml.v3"
)

type FixPlan struct {
	FilePath    string
	Description string
	Original    []byte
	Modified    []byte
	Diff        string
	Applied     bool
}

type Fixer struct {
	dryRun bool
}

func New(dryRun bool) *Fixer {
	return &Fixer{dryRun: dryRun}
}

func (f *Fixer) Fix(filePath string, diags []model.Diagnostic) ([]FixPlan, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var plans []FixPlan

	for _, d := range diags {
		switch d.RuleID {
		case "OTEL-REL-102":
			plan, err := f.fixMemLimiterOrder(filePath, data)
			if err != nil {
				return nil, fmt.Errorf("planning fix %s: %w", d.RuleID, err)
			}
			if plan != nil {
				plans = append(plans, *plan)
			}
		}
	}

	for i := range plans {
		if f.dryRun {
			plans[i].Diff = unifiedDiff(plans[i].FilePath, plans[i].Original, plans[i].Modified)
		} else {
			perm := originalPerm(plans[i].FilePath, 0644)
			if err := os.WriteFile(plans[i].FilePath, plans[i].Modified, perm); err != nil {
				return nil, fmt.Errorf("writing file: %w", err)
			}
			plans[i].Applied = true
		}
	}

	return plans, nil
}

func (f *Fixer) fixMemLimiterOrder(filePath string, data []byte) (*FixPlan, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	if len(doc.Content) == 0 {
		return nil, nil
	}

	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, nil
	}

	// Find the processor sequence node and locate memory_limiter position.
	// Record the line number of the processors line and the mem_limiter item.
	type procFix struct {
		procLine    int // line of "processors: [a, b, ...]" in original YAML
		newList     string
	}

	var fixes []procFix

	serviceVal := findValue(root, "service")
	if serviceVal == nil {
		return nil, nil
	}
	pipelinesVal := findValue(serviceVal, "pipelines")
	if pipelinesVal == nil || pipelinesVal.Kind != yaml.MappingNode {
		return nil, nil
	}

	for i := 0; i < len(pipelinesVal.Content)-1; i += 2 {
		pipelineVal := pipelinesVal.Content[i+1]
		if pipelineVal.Kind != yaml.MappingNode {
			continue
		}

		procKey := findKey(pipelineVal, "processors")
		if procKey == nil {
			continue
		}
		procVal := findValue(pipelineVal, "processors")
		if procVal == nil || procVal.Kind != yaml.SequenceNode {
			continue
		}

		var ids []string
		memIdx := -1
		for idx, item := range procVal.Content {
			if item.Kind == yaml.ScalarNode {
				ids = append(ids, item.Value)
				if processorType(item.Value) == "memory_limiter" {
					memIdx = idx
				}
			}
		}

		if memIdx <= 0 {
			continue
		}

		mem := ids[memIdx]
		newIDs := append([]string{mem}, ids[:memIdx]...)
		newIDs = append(newIDs, ids[memIdx+1:]...)

		newList := "[" + strings.Join(newIDs, ", ") + "]"

		fixes = append(fixes, procFix{
			procLine: procKey.Line,
			newList:  newList,
		})
	}

	if len(fixes) == 0 {
		return nil, nil
	}

	// Apply text-level edits: replace only the processor lines.
	lines := strings.Split(string(data), "\n")
	for _, fx := range fixes {
		idx := fx.procLine - 1
		if idx >= 0 && idx < len(lines) {
			oldLine := lines[idx]
			colon := strings.Index(oldLine, ":")
			if colon >= 0 {
				indent := oldLine[:colon]
				lines[idx] = indent + ": " + fx.newList
			}
		}
	}
	modified := []byte(strings.Join(lines, "\n"))

	// Validate: parse the modified YAML to ensure it's valid.
	var validate yaml.Node
	if err := yaml.Unmarshal(modified, &validate); err != nil {
		return nil, fmt.Errorf("autofix produced invalid YAML; aborting: %w", err)
	}

	return &FixPlan{
		FilePath:    filePath,
		Description: "Move memory_limiter to first position in processor chain",
		Original:    data,
		Modified:    modified,
	}, nil
}

func findValue(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content)-1; i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func findKey(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content)-1; i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i]
		}
	}
	return nil
}

func processorType(id string) string {
	if idx := strings.Index(id, "/"); idx >= 0 {
		return id[:idx]
	}
	return id
}

func unifiedDiff(file string, orig, mod []byte) string {
	origLines := strings.SplitAfter(string(orig), "\n")
	modLines := strings.SplitAfter(string(mod), "\n")

	if strings.HasSuffix(string(orig), "\n") {
		origLines = origLines[:len(origLines)-1]
	}
	if strings.HasSuffix(string(mod), "\n") {
		modLines = modLines[:len(modLines)-1]
	}

	var out strings.Builder
	out.WriteString(fmt.Sprintf("--- %s\n", file))
	out.WriteString(fmt.Sprintf("+++ %s\n", file))

	// Compute hunk line ranges
	origLen, modLen := len(origLines), len(modLines)
	out.WriteString(fmt.Sprintf("@@ -1,%d +1,%d @@\n", origLen, modLen))

	i, j := 0, 0
	for i < origLen || j < modLen {
		if i < origLen && j < modLen && origLines[i] == modLines[j] {
			out.WriteString(" " + origLines[i])
			i++
			j++
		} else if j < modLen {
			out.WriteString("+" + modLines[j])
			j++
			if i < origLen && j < modLen && origLines[i] == modLines[j] {
				continue
			}
			if i < origLen {
				out.WriteString("-" + origLines[i])
				i++
			}
		} else {
			out.WriteString("-" + origLines[i])
			i++
		}
	}

	return out.String()
}

func originalPerm(path string, fallback os.FileMode) os.FileMode {
	fi, err := os.Stat(path)
	if err != nil {
		return fallback
	}
	return fi.Mode().Perm()
}
