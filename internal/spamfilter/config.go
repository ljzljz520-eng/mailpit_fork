package spamfilter

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/axllent/mailpit/internal/logger"
	"github.com/goccy/go-yaml"
)

// yamlConfig is the on-disk YAML configuration for the spam filter.
type yamlConfig struct {
	Threshold *float64   `yaml:"threshold"`
	Tag       *string    `yaml:"tag"`
	Disable   []string   `yaml:"disable"`
	Allowlist []string   `yaml:"allowlist"`
	Blocklist []string   `yaml:"blocklist"`
	Rules     []yamlRule `yaml:"rules"`
}

// yamlRule is a single user-defined rule.
type yamlRule struct {
	Name        string  `yaml:"name"`
	Description string  `yaml:"description"`
	Score       float64 `yaml:"score"`
	Pattern     string  `yaml:"pattern"`
	Target      string  `yaml:"target"`
	Header      string  `yaml:"header"`
}

// resetState restores the default rule set and settings.
func resetState() {
	scoreThreshold = defaultThreshold
	spamTag = defaultTag
	activeRules = builtinRules()
	builtInCount = len(activeRules)
	customCount = 0
	allowList = []listEntry{}
	blockList = []listEntry{}
}

// LoadConfig loads the spam filter configuration from the given YAML file.
// An empty path restores the built-in defaults (preset rules, threshold 5.0,
// "spam" tag). Missing files, malformed YAML, invalid regular expressions and
// rule definitions return an error so the application fails fast at startup.
func LoadConfig(path string) error {
	mu.Lock()
	defer mu.Unlock()

	resetState()

	if path == "" {
		return nil
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("[spam-filter] configuration file not found or unreadable: %w", err)
	}

	conf := yamlConfig{}
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return fmt.Errorf("[spam-filter] parsing %s: %w", path, err)
	}

	if conf.Threshold != nil {
		if *conf.Threshold <= 0 {
			return fmt.Errorf("[spam-filter] threshold must be greater than 0")
		}
		scoreThreshold = *conf.Threshold
	}

	if conf.Tag != nil {
		spamTag = strings.TrimSpace(*conf.Tag)
	}

	// disable preset rules by ID
	disabled := map[string]bool{}
	for _, id := range conf.Disable {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		upper := strings.ToUpper(id)
		if _, found := builtInRuleIDs()[upper]; !found {
			logger.Log().Warnf("[spam-filter] ignoring unknown built-in rule ID in disable list: %s", id)
			continue
		}
		disabled[upper] = true
	}

	rules := make([]matcherRule, 0, len(activeRules))
	for _, r := range activeRules {
		if disabled[r.id] {
			continue
		}
		rules = append(rules, r)
	}
	activeRules = rules
	builtInCount = len(rules)

	allowList = parseListEntries(conf.Allowlist)
	blockList = parseListEntries(conf.Blocklist)

	// custom user rules
	for i, yr := range conf.Rules {
		name := strings.TrimSpace(yr.Name)
		if name == "" {
			return fmt.Errorf("[spam-filter] rules[%d] is missing a name", i)
		}
		pattern := strings.TrimSpace(yr.Pattern)
		if pattern == "" {
			return fmt.Errorf("[spam-filter] rule %q is missing a pattern", name)
		}
		target := strings.TrimSpace(yr.Target)
		if target == "" {
			target = "all"
		}
		target = strings.ToLower(target)
		if target == "header" && strings.TrimSpace(yr.Header) == "" {
			return fmt.Errorf("[spam-filter] rule %q uses target \"header\" but no header name is set", name)
		}
		if !validRuleTargets[target] {
			return fmt.Errorf("[spam-filter] rule %q has invalid target %q (valid: from, subject, body, header, attachment, all)", name, yr.Target)
		}

		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return fmt.Errorf("[spam-filter] rule %q has an invalid pattern: %w", name, err)
		}

		id := name
		if _, isBuiltIn := builtInRuleIDs()[strings.ToUpper(name)]; isBuiltIn {
			logger.Log().Warnf("[spam-filter] ignoring custom rule %q: name conflicts with a built-in rule ID", name)
			continue
		}

		description := strings.TrimSpace(yr.Description)
		if description == "" {
			description = fmt.Sprintf("Custom rule (%s)", name)
		}
		headerName := strings.TrimSpace(yr.Header)

		activeRules = append(activeRules, matcherRule{
			id:          id,
			description: description,
			score:       yr.Score,
			builtin:     false,
			fn:          userRuleMatcher(re, target, headerName),
		})
		customCount++
	}

	return nil
}

var validRuleTargets = map[string]bool{
	"from":       true,
	"subject":    true,
	"body":       true,
	"header":     true,
	"attachment": true,
	"all":        true,
}

// userRuleMatcher builds a matcher for a compiled user rule.
func userRuleMatcher(re *regexp.Regexp, target, headerName string) func(m *message) bool {
	return func(m *message) bool {
		switch target {
		case "from":
			return re.MatchString(m.from) || re.MatchString(m.fromName)
		case "subject":
			return re.MatchString(m.subject)
		case "body":
			return re.MatchString(m.text) || re.MatchString(m.html)
		case "header":
			return re.MatchString(m.header(headerName))
		case "attachment":
			for _, name := range m.attachments {
				if re.MatchString(name) {
					return true
				}
			}
			return false
		default: // "all"
			if re.MatchString(m.from) || re.MatchString(m.fromName) ||
				re.MatchString(m.subject) || re.MatchString(m.text) || re.MatchString(m.html) {
				return true
			}
			for _, name := range m.attachments {
				if re.MatchString(name) {
					return true
				}
			}
			return false
		}
	}
}

// parseListEntries converts allowlist/blocklist YAML entries into listEntry
// values, accepting full email addresses or domains.
func parseListEntries(entries []string) []listEntry {
	out := []listEntry{}
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if parts := strings.SplitN(e, "@", 2); len(parts) == 2 {
			out = append(out, listEntry{email: strings.TrimSpace(parts[0]) + "@" + strings.TrimSpace(parts[1])})
			continue
		}
		// strip leading wildcard notation (e.g. *.example.com)
		dom := strings.TrimPrefix(e, "*.")
		out = append(out, listEntry{domain: dom})
	}
	return out
}

// builtInRuleIDs returns a set of the preset rule IDs.
func builtInRuleIDs() map[string]bool {
	ids := map[string]bool{}
	for _, r := range builtinRules() {
		ids[r.id] = true
	}
	return ids
}
