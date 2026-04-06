package guard

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func SplitAllowEntries(values []string) ([]string, []string, error) {
	var ips []string
	var cidrs []string

	for _, raw := range values {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return nil, nil, fmt.Errorf("invalid CIDR %q: %w", entry, err)
			}
			cidrs = append(cidrs, entry)
			continue
		}

		ip := net.ParseIP(entry).To4()
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IPv4 address %q", entry)
		}
		ips = append(ips, entry)
	}

	return ips, cidrs, nil
}

func LoadAllowlistFile(path string) ([]string, []string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open allowlist file %q: %w", path, err)
	}
	defer file.Close()

	var entries []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan allowlist file %q: %w", path, err)
	}

	return SplitAllowEntries(entries)
}

func DedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
