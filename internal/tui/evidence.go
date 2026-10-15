package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const maxEvidenceViewBytes = 4 << 20

func (m *model) openFindingEvidence(finding storage.Finding) {
	m.evidenceView, m.evidenceTop = true, 0
	m.evidencePath, m.evidenceError, m.evidenceLines = finding.ArtifactPath, "", nil
	path, err := m.safeEvidencePath(finding.ArtifactPath)
	if err != nil {
		m.evidenceError = err.Error()
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		m.evidenceError = "evidence unavailable: " + err.Error()
		return
	}
	if !info.Mode().IsRegular() {
		m.evidenceError = "evidence is not a regular text file"
		return
	}
	if info.Size() > maxEvidenceViewBytes {
		m.evidenceError = fmt.Sprintf("evidence exceeds the %d-byte viewer limit", maxEvidenceViewBytes)
		return
	}
	file, err := os.Open(path)
	if err != nil {
		m.evidenceError = "evidence unavailable: " + err.Error()
		return
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, maxEvidenceViewBytes+1))
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			m.evidenceLines = append(m.evidenceLines, strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			m.evidenceError = "evidence read failed: " + readErr.Error()
			return
		}
	}
	if len(m.evidenceLines) == 0 {
		m.evidenceLines = []string{"(empty artifact)"}
	}
}

func (m *model) safeEvidencePath(raw string) (string, error) {
	root, err := filepath.Abs(m.cfg.ResultsRoot())
	if err != nil {
		return "", fmt.Errorf("invalid results root")
	}
	path := raw
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	path, err = filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("invalid evidence path")
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("evidence path is outside the assessment results")
	}
	current := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		entry, statErr := os.Lstat(current)
		if statErr != nil {
			return "", statErr
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink evidence paths are not allowed")
		}
	}
	return path, nil
}
