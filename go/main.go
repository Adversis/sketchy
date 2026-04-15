package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

// RiskLevel represents the severity of a finding
type RiskLevel string

const (
	HighRisk   RiskLevel = "HIGH RISK"
	MediumRisk RiskLevel = "MEDIUM RISK"
	LowRisk    RiskLevel = "LOW RISK"
	Suspicious RiskLevel = "SUSPICIOUS"
)

// FilterLevel represents the filtering mode
type FilterLevel string

const (
	FilterAll    FilterLevel = "ALL"
	FilterHigh   FilterLevel = "HIGH"
	FilterMedium FilterLevel = "MEDIUM"
)

// Pattern represents a detection pattern
type Pattern struct {
	Name        string
	Risk        RiskLevel
	Description string
	Regex        *regexp.Regexp
	FileTypes    []string                  // Suffix match (filename/ext). Empty means no suffix filter.
	PathContains []string                  // Path substring match (e.g., ".claude/skills/"). Empty means no path filter.
	Validator    func(content string) bool // Additional validation beyond regex
}

// Scanner holds the scanner configuration
type Scanner struct {
	Patterns    []Pattern
	FilterLevel FilterLevel
	IssuesFound int
	ScanPath    string
	SkipBinary  bool
	MaxFileSize int64
	IgnoreDirs  map[string]struct{}
	JSONOutput  bool
	Findings    []Finding
}

// Finding is a single scan result, shaped for stable JSON consumers
// (git hooks, the forthcoming VSCode extension).
type Finding struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Preview     string `json:"preview"`
}

// Color functions
var (
	red    = color.New(color.FgRed).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	blue   = color.New(color.FgBlue).SprintFunc()
	purple = color.New(color.FgMagenta).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
)

func main() {
	var (
		highOnly   = flag.Bool("high-only", false, "Only show HIGH RISK findings")
		mediumUp   = flag.Bool("medium-up", false, "Show MEDIUM and HIGH RISK findings")
		help       = flag.Bool("help", false, "Show help")
		skipBinary = flag.Bool("skip-binary", true, "Skip binary files")
		ignore     = flag.String("ignore", "", "Comma-separated dir names to skip (any nested occurrence), e.g. node_modules,vendor")
		jsonOut    = flag.Bool("json", false, "Emit findings as a single JSON object (suppresses human output)")
	)
	flag.Usage = printHelp

	flag.Parse()

	if *help || (flag.NFlag() == 0 && flag.NArg() == 0) {
		printHelp()
		os.Exit(0)
	}

	scanPath := "."
	if flag.NArg() > 0 {
		scanPath = flag.Arg(0)
	}

	filterLevel := FilterAll
	if *highOnly {
		filterLevel = FilterHigh
	} else if *mediumUp {
		filterLevel = FilterMedium
	}

	ignoreDirs := parseIgnoreList(*ignore)
	scanner := NewScanner(scanPath, filterLevel, *skipBinary, ignoreDirs)
	scanner.JSONOutput = *jsonOut

	if !*jsonOut {
		fmt.Printf("%s\n", yellow("🔍 Scanning: "+scanPath))
		fmt.Println("================================")
	}

	if err := scanner.Scan(); err != nil {
		if *jsonOut {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}

	if *jsonOut {
		out := struct {
			ScanPath    string    `json:"scan_path"`
			IssuesFound int       `json:"issues_found"`
			Findings    []Finding `json:"findings"`
		}{scanPath, scanner.IssuesFound, scanner.Findings}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		scanner.PrintSummary()
	}
	os.Exit(scanner.IssuesFound)
}

func printHelp() {
	fmt.Println("sketchy - Security scanner for repositories")
	fmt.Println("\nUsage: sketchy [options] [path]")
	fmt.Println("\nScans [path] (default: current directory) for suspicious patterns.")
	fmt.Println("\nOptions:")
	fmt.Println("  -high-only        Only show HIGH RISK findings")
	fmt.Println("  -medium-up        Show MEDIUM and HIGH RISK findings")
	fmt.Println("  -ignore string    Comma-separated dir names to skip (any nested occurrence)")
	fmt.Println("  -skip-binary      Skip binary files (default true)")
	fmt.Println("  -json             Emit findings as JSON (suppresses human output)")
	fmt.Println("  -help             Show this help message")
	fmt.Println("\nExamples:")
	fmt.Println("  sketchy                                   # scan current directory")
	fmt.Println("  sketchy ./some-repo                       # scan a specific path")
	fmt.Println("  sketchy -high-only ./repo                 # only show HIGH RISK findings")
	fmt.Println("  sketchy -ignore node_modules,vendor .     # skip noisy dep dirs")
}

// NewScanner creates a new scanner instance
func NewScanner(path string, filter FilterLevel, skipBinary bool, ignoreDirs map[string]struct{}) *Scanner {
	s := &Scanner{
		ScanPath:    path,
		FilterLevel: filter,
		SkipBinary:  skipBinary,
		MaxFileSize: 1024 * 1024, // 1MB
		IgnoreDirs:  ignoreDirs,
	}
	s.initPatterns()
	return s
}

func parseIgnoreList(s string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, raw := range strings.Split(s, ",") {
		name := strings.TrimSpace(raw)
		if name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

// Scan performs the security scan
func (s *Scanner) Scan() error {
	if _, err := os.Stat(s.ScanPath); err != nil {
		return err
	}

	return filepath.WalkDir(s.ScanPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if _, skip := s.IgnoreDirs[d.Name()]; skip && path != s.ScanPath {
				return filepath.SkipDir
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil || info.Size() > s.MaxFileSize {
			return nil
		}

		if s.shouldSkipFile(path) {
			return nil
		}

		s.checkFile(path)
		return nil
	})
}

// shouldSkipFile determines if a file should be skipped
func (s *Scanner) shouldSkipFile(path string) bool {
	// Skip hidden directories (like .git) — but keep scanning AI-agent
	// config/instruction dirs (.claude, .cursor, .codex, .continue, .gemini,
	// .windsurf) since those are a primary target of the scanner.
	dir := filepath.ToSlash(filepath.Dir(path))
	if strings.Contains(dir, "/.") && !containsAgentDir(dir) {
		return true
	}

	// Skip common binary/media extensions
	ext := strings.ToLower(filepath.Ext(path))
	skipExts := []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
		".mp3", ".mp4", ".avi", ".mov", ".wmv",
		".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
		".exe", ".dll", ".so", ".dylib", ".bin",
		".pdf", ".doc", ".docx", ".xls", ".xlsx",
		".pyc", ".pyo", ".class", ".jar",
		".woff", ".woff2", ".ttf", ".eot",
	}

	for _, skipExt := range skipExts {
		if ext == skipExt {
			return true
		}
	}

	// Check if binary
	if s.SkipBinary {
		if isBinary, _ := isBinaryFile(path); isBinary {
			return true
		}
	}

	return false
}

// isBinaryFile checks if a file appears to be binary
func isBinaryFile(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	// Read first 512 bytes
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return false, err
	}
	buf = buf[:n]

	// Check for null bytes (common in binary files)
	if bytes.Contains(buf, []byte{0}) {
		return true, nil
	}

	// Check if mostly printable ASCII
	nonPrintable := 0
	for _, b := range buf {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintable++
		}
	}

	return float64(nonPrintable)/float64(len(buf)) > 0.3, nil
}

// checkFile scans a single file for patterns
func (s *Scanner) checkFile(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	contentStr := string(content)
	relPath, _ := filepath.Rel(s.ScanPath, path)

	// Normalize path separators so PathContains rules written with forward
	// slashes match on Windows too.
	normPath := filepath.ToSlash(path)

	for _, pattern := range s.Patterns {
		// A pattern is scoped if either FileTypes or PathContains is set.
		// When scoped, the file must match at least one entry from either list.
		if len(pattern.FileTypes) > 0 || len(pattern.PathContains) > 0 {
			matched := false
			for _, ft := range pattern.FileTypes {
				if strings.HasSuffix(path, ft) {
					matched = true
					break
				}
			}
			if !matched {
				for _, pc := range pattern.PathContains {
					if strings.Contains(normPath, pc) {
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}
		}

		// Check pattern
		if pattern.Regex != nil && pattern.Validator != nil {
			// Pattern with both regex and validator
			if pattern.Validator(contentStr) {
				matches := pattern.Regex.FindAllStringIndex(contentStr, 3)
				if len(matches) > 0 {
					if s.shouldDisplay(pattern.Risk) {
						s.recordMatch(pattern, relPath, contentStr, matches)
					}
					s.IssuesFound++
				}
			}
		} else if pattern.Regex != nil {
			// Pattern with regex only
			matches := pattern.Regex.FindAllStringIndex(contentStr, 3)
			if len(matches) > 0 {
				if s.shouldDisplay(pattern.Risk) {
					s.recordMatch(pattern, relPath, contentStr, matches)
				}
				s.IssuesFound++
			}
		} else if pattern.Validator != nil {
			// Pattern with validator only (e.g., for binary detection)
			if pattern.Validator(contentStr) {
				if s.shouldDisplay(pattern.Risk) {
					s.recordValidatorMatch(pattern, relPath)
				}
				s.IssuesFound++
			}
		}
	}
}

// shouldDisplay checks if a risk level should be displayed based on filter
func (s *Scanner) shouldDisplay(risk RiskLevel) bool {
	switch s.FilterLevel {
	case FilterHigh:
		return risk == HighRisk
	case FilterMedium:
		return risk == HighRisk || risk == MediumRisk
	default:
		return true
	}
}

// recordMatch routes a regex match to either the JSON buffer or stdout.
func (s *Scanner) recordMatch(pattern Pattern, file string, content string, matches [][]int) {
	if s.JSONOutput {
		for i, m := range matches {
			if i >= 3 {
				break
			}
			lineNum, preview := getLineInfo(content, m[0])
			if len(preview) > 200 {
				preview = preview[:200]
			}
			s.Findings = append(s.Findings, Finding{
				Name:        pattern.Name,
				Description: pattern.Description,
				Risk:        string(pattern.Risk),
				File:        file,
				Line:        lineNum,
				Preview:     preview,
			})
		}
		return
	}
	s.printMatch(pattern, file, content, matches)
}

// recordValidatorMatch routes a validator-only match to JSON or stdout.
func (s *Scanner) recordValidatorMatch(pattern Pattern, file string) {
	if s.JSONOutput {
		s.Findings = append(s.Findings, Finding{
			Name:        pattern.Name,
			Description: pattern.Description,
			Risk:        string(pattern.Risk),
			File:        file,
			Preview:     "[Requires manual review]",
		})
		return
	}
	s.printValidatorMatch(pattern, file)
}

// printMatch prints a pattern match
func (s *Scanner) printMatch(pattern Pattern, file string, content string, matches [][]int) {
	riskColor := s.getRiskColor(pattern.Risk)
	fmt.Printf("%s %s - %s\n", riskColor(string(pattern.Risk)), riskColor(pattern.Description), pattern.Name)

	for i, match := range matches {
		if i >= 3 {
			break // Only show first 3 matches
		}

		lineNum, preview := getLineInfo(content, match[0])
		fmt.Printf("%s  File: %s:%d\n", blue(""), file, lineNum)

		if len(preview) > 80 {
			preview = preview[:80] + "..."
		}
		fmt.Printf("  Preview: %s\n\n", preview)
	}
}

// printValidatorMatch prints a match found by validator only
func (s *Scanner) printValidatorMatch(pattern Pattern, file string) {
	riskColor := s.getRiskColor(pattern.Risk)
	fmt.Printf("%s %s - %s\n", riskColor(string(pattern.Risk)), riskColor(pattern.Description), pattern.Name)
	fmt.Printf("%s  File: %s\n", blue(""), file)
	fmt.Printf("  Preview: [Requires manual review]\n\n")
}

// getRiskColor returns the appropriate color function for a risk level
func (s *Scanner) getRiskColor(risk RiskLevel) func(a ...interface{}) string {
	switch risk {
	case HighRisk:
		return red
	case MediumRisk:
		return yellow
	case LowRisk:
		return yellow
	case Suspicious:
		return purple
	default:
		return fmt.Sprint
	}
}

// getLineInfo gets line number and content for a position
func getLineInfo(content string, pos int) (int, string) {
	lineNum := 1
	lineStart := 0

	for i := 0; i < pos && i < len(content); i++ {
		if content[i] == '\n' {
			lineNum++
			lineStart = i + 1
		}
	}

	lineEnd := pos
	for lineEnd < len(content) && content[lineEnd] != '\n' {
		lineEnd++
	}

	line := strings.TrimSpace(content[lineStart:lineEnd])
	return lineNum, line
}

// PrintSummary prints the scan summary
func (s *Scanner) PrintSummary() {
	fmt.Println("================================")
	if s.IssuesFound == 0 {
		fmt.Printf("%s\n", green("✅ Scan complete. No suspicious patterns detected."))
	} else {
		fmt.Printf("%s\n", red(fmt.Sprintf("⚠️  Scan complete. Found %d potential issue(s).", s.IssuesFound)))
	}
}

// checkForBidiChars checks for bidirectional Unicode characters
func checkForBidiChars(content string) bool {
	// Check for bidirectional override characters
	bidiChars := []rune{
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // LTR/RTL embedding
		0x2066, 0x2067, 0x2068, 0x2069, // Isolate characters
	}

	for _, char := range bidiChars {
		if strings.ContainsRune(content, char) {
			return true
		}
	}

	// Also check raw bytes for these UTF-8 sequences
	contentBytes := []byte(content)
	bidiPatterns := [][]byte{
		{0xe2, 0x80, 0xaa}, {0xe2, 0x80, 0xab}, {0xe2, 0x80, 0xac},
		{0xe2, 0x80, 0xad}, {0xe2, 0x80, 0xae},
		{0xe2, 0x81, 0xa6}, {0xe2, 0x81, 0xa7}, {0xe2, 0x81, 0xa8}, {0xe2, 0x81, 0xa9},
	}

	for _, pattern := range bidiPatterns {
		if bytes.Contains(contentBytes, pattern) {
			return true
		}
	}

	return false
}

// checkForCyrillic checks for Cyrillic characters (homograph attacks)
func checkForCyrillic(content string) bool {
	for _, r := range content {
		if r >= 0x0400 && r <= 0x04FF {
			return true
		}
	}
	return false
}

// checkForNonASCII checks for non-ASCII characters
func checkForNonASCII(content string) bool {
	for _, r := range content {
		if r > 127 {
			return true
		}
	}
	return false
}
