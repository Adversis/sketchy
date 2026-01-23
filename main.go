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
	"time"

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
	Regex       *regexp.Regexp
	FileTypes   []string                  // Empty means all files
	Validator   func(content string) bool // Additional validation beyond regex
}

// Finding represents a single finding for JSON output
type Finding struct {
	PatternName string    `json:"pattern_name"`
	Risk        RiskLevel `json:"risk"`
	Description string    `json:"description"`
	FilePath    string    `json:"file_path"`
	LineNumber  int       `json:"line_number,omitempty"`
	Preview     string    `json:"preview"`
}

// ScanResult represents the complete scan output for JSON
type ScanResult struct {
	ScanPath    string    `json:"scan_path"`
	Timestamp   string    `json:"timestamp"`
	FilterLevel string    `json:"filter_level"`
	TotalIssues int       `json:"total_issues"`
	Findings    []Finding `json:"findings"`
}

// Scanner holds the scanner configuration
type Scanner struct {
	Patterns    []Pattern
	FilterLevel FilterLevel
	IssuesFound int
	ScanPath    string
	SkipBinary  bool
	MaxFileSize int64
	JSONOutput  bool
	Findings    []Finding
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
		scanPath   = flag.String("path", ".", "Path to scan")
		highOnly   = flag.Bool("high-only", false, "Only show HIGH RISK findings")
		mediumUp   = flag.Bool("medium-up", false, "Show MEDIUM and HIGH RISK findings")
		help       = flag.Bool("help", false, "Show help")
		skipBinary = flag.Bool("skip-binary", true, "Skip binary files")
		jsonOutput = flag.Bool("json", false, "Output results in JSON format")
	)

	flag.Parse()

	if *help || (flag.NFlag() == 0 && flag.NArg() == 0) {
		printHelp()
		os.Exit(0)
	}

	// Handle positional argument
	if flag.NArg() > 0 {
		*scanPath = flag.Arg(0)
	}

	filterLevel := FilterAll
	if *highOnly {
		filterLevel = FilterHigh
	} else if *mediumUp {
		filterLevel = FilterMedium
	}

	scanner := NewScanner(*scanPath, filterLevel, *skipBinary, *jsonOutput)

	if !*jsonOutput {
		fmt.Printf("%s\n", yellow("🔍 Scanning: "+*scanPath))
		fmt.Println("================================")
	}

	if err := scanner.Scan(); err != nil {
		if *jsonOutput {
			json.NewEncoder(os.Stderr).Encode(map[string]string{"error": err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}

	scanner.Output()
	os.Exit(scanner.IssuesFound)
}

func printHelp() {
	fmt.Println("sketchy - Security scanner for repositories")
	fmt.Println("\nUsage: sketchy [options] [path]")
	fmt.Println("\nOptions:")
	fmt.Println("  -path string      Path to scan (default \".\")")
	fmt.Println("  -high-only        Only show HIGH RISK findings")
	fmt.Println("  -medium-up        Show MEDIUM and HIGH RISK findings")
	fmt.Println("  -skip-binary      Skip binary files (default true)")
	fmt.Println("  -json             Output results in JSON format")
	fmt.Println("  -help             Show this help message")
}

// NewScanner creates a new scanner instance
func NewScanner(path string, filter FilterLevel, skipBinary bool, jsonOutput bool) *Scanner {
	s := &Scanner{
		ScanPath:    path,
		FilterLevel: filter,
		SkipBinary:  skipBinary,
		MaxFileSize: 1024 * 1024, // 1MB
		JSONOutput:  jsonOutput,
		Findings:    []Finding{},
	}
	s.initPatterns()
	return s
}

// Scan performs the security scan
func (s *Scanner) Scan() error {
	return filepath.Walk(s.ScanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip directories and special files
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}

		// Skip files that are too large
		if info.Size() > s.MaxFileSize {
			return nil
		}

		// Skip common non-text files
		if s.shouldSkipFile(path) {
			return nil
		}

		// Check the file
		s.checkFile(path)
		return nil
	})
}

// shouldSkipFile determines if a file should be skipped
func (s *Scanner) shouldSkipFile(path string) bool {
	// Skip hidden directories (like .git)
	dir := filepath.Dir(path)
	if strings.Contains(dir, "/.") {
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

	for _, pattern := range s.Patterns {
		// Check if pattern applies to this file type
		if len(pattern.FileTypes) > 0 {
			matched := false
			for _, ft := range pattern.FileTypes {
				if strings.HasSuffix(path, ft) {
					matched = true
					break
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

// recordMatch collects a pattern match as findings
func (s *Scanner) recordMatch(pattern Pattern, file string, content string, matches [][]int) {
	for i, match := range matches {
		if i >= 3 {
			break // Only record first 3 matches
		}

		lineNum, preview := getLineInfo(content, match[0])
		if len(preview) > 80 {
			preview = preview[:80] + "..."
		}

		s.Findings = append(s.Findings, Finding{
			PatternName: pattern.Name,
			Risk:        pattern.Risk,
			Description: pattern.Description,
			FilePath:    file,
			LineNumber:  lineNum,
			Preview:     preview,
		})
	}
}

// recordValidatorMatch collects a validator-only match as a finding
func (s *Scanner) recordValidatorMatch(pattern Pattern, file string) {
	s.Findings = append(s.Findings, Finding{
		PatternName: pattern.Name,
		Risk:        pattern.Risk,
		Description: pattern.Description,
		FilePath:    file,
		LineNumber:  0,
		Preview:     "[Requires manual review]",
	})
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

// Output outputs scan results in the configured format
func (s *Scanner) Output() {
	if s.JSONOutput {
		s.outputJSON()
	} else {
		s.outputText()
	}
}

// outputText prints findings and summary in human-readable format
func (s *Scanner) outputText() {
	// Group findings by pattern for cleaner output
	type patternKey struct {
		name string
		file string
	}
	printed := make(map[patternKey]bool)

	for _, f := range s.Findings {
		key := patternKey{f.PatternName, f.FilePath}
		riskColor := s.getRiskColor(f.Risk)

		// Print pattern header only once per pattern+file combo
		if !printed[key] {
			fmt.Printf("%s %s - %s\n", riskColor(string(f.Risk)), riskColor(f.Description), f.PatternName)
			printed[key] = true
		}

		if f.LineNumber > 0 {
			fmt.Printf("  File: %s:%d\n", f.FilePath, f.LineNumber)
		} else {
			fmt.Printf("  File: %s\n", f.FilePath)
		}
		fmt.Printf("  Preview: %s\n\n", f.Preview)
	}

	// Summary
	fmt.Println("================================")
	if s.IssuesFound == 0 {
		fmt.Printf("%s\n", green("✅ Scan complete. No suspicious patterns detected."))
	} else {
		fmt.Printf("%s\n", red(fmt.Sprintf("⚠️  Scan complete. Found %d potential issue(s).", s.IssuesFound)))
	}
}

// outputJSON outputs the scan results in JSON format
func (s *Scanner) outputJSON() {
	result := ScanResult{
		ScanPath:    s.ScanPath,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		FilterLevel: string(s.FilterLevel),
		TotalIssues: s.IssuesFound,
		Findings:    s.Findings,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(result)
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
