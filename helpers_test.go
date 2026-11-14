package main

import "testing"

// useMemoryHAR routes HAR entries to memory for the duration of a test.
func useMemoryHAR(t *testing.T) *harWriter {
	t.Helper()
	saved, savedHM, savedCaptures := har, harMode, captures
	har, harMode, captures = &harWriter{keep: true}, true, newExchangeJoiner()
	t.Cleanup(func() { har, harMode, captures = saved, savedHM, savedCaptures })
	return har
}

// entries returns the HAR entries written so far.
func (w *harWriter) entries() []harEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]harEntry(nil), w.kept...)
}

// harFile is the shape of a HAR file, for reading one back.
type harFile struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"creator"`
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

// writeHARForTest writes entries to a HAR file the way a run does.
func writeHARForTest(path string, entries ...harEntry) error {
	saved := har
	defer func() { har = saved }()
	if err := openHARFile(path); err != nil {
		return err
	}
	for _, e := range entries {
		har.add(e)
	}
	return closeHAR()
}
