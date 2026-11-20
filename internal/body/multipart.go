package body

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"unicode/utf8"
)

// Part is one part of a multipart/form-data or multipart/* body.
type Part struct {
	Name        string `json:"name,omitempty"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size"`
	Value       string `json:"value,omitempty"`
	Binary      bool   `json:"binary,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// MultipartBoundary extracts the boundary parameter of a multipart/* Content-Type.
func MultipartBoundary(ct string) (string, bool) {
	if ct == "" {
		return "", false
	}
	media, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.HasPrefix(strings.ToLower(media), "multipart/") {
		return "", false
	}
	b := params["boundary"]
	return b, b != ""
}

// DecodeMultipart dissects a multipart body into its parts, tolerating a
// captured prefix whose closing boundary was cut off.
func DecodeMultipart(data []byte, boundary string, budget int) ([]Part, bool) {
	mr := multipart.NewReader(bytes.NewReader(data), boundary)
	var parts []Part
	truncated := false
	perPart := max(budget/4, 200)
	const maxParts = 32

	for len(parts) < maxParts {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			truncated = true
			break
		}
		ct := p.Header.Get("Content-Type")
		// Read up to perPart+1 bytes for preview, and count the rest.
		head, readErr := io.ReadAll(io.LimitReader(p, int64(perPart+4)))
		rest, copyErr := io.Copy(io.Discard, p)
		_ = p.Close()
		partTrunc := (readErr != nil && !errors.Is(readErr, io.EOF)) || (copyErr != nil && !errors.Is(copyErr, io.EOF))
		total := int64(len(head)) + rest

		pt := Part{
			Name:        p.FormName(),
			Filename:    p.FileName(),
			ContentType: ct,
			Size:        total,
			Truncated:   partTrunc,
		}
		if len(head) > 0 {
			sample := trimPartialRune(head, len(head) > perPart || partTrunc)
			if PrintableType(ct) && utf8.Valid(sample) && !hasBinaryNull(sample) {
				s := string(sample)
				if len(s) > perPart || rest > 0 {
					s = clipUTF8(s, perPart)
					pt.Truncated = true
				}
				pt.Value = s
			} else {
				pt.Binary = true
			}
		}
		parts = append(parts, pt)
		if partTrunc {
			truncated = true
			break
		}
	}
	return parts, truncated
}

func hasBinaryNull(b []byte) bool {
	return bytes.IndexByte(b, 0) >= 0
}

// FormatPartsText renders multipart parts concisely for text output and TUI.
func FormatPartsText(parts []Part) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[multipart: %d part(s)]", len(parts))
	for i, p := range parts {
		b.WriteByte('\n')
		label := fmt.Sprintf("#%d", i+1)
		if p.Name != "" {
			label = fmt.Sprintf("%q", p.Name)
		}
		meta := fmt.Sprintf("%d B", p.Size)
		if p.Filename != "" {
			meta = fmt.Sprintf("file=%q, %s", p.Filename, meta)
		}
		if p.ContentType != "" {
			meta = p.ContentType + ", " + meta
		}
		if p.Binary {
			fmt.Fprintf(&b, "  part %s (%s): [binary]", label, meta)
		} else {
			val := p.Value
			if p.Truncated && val != "" {
				val += "…"
			}
			fmt.Fprintf(&b, "  part %s (%s): %s", label, meta, val)
		}
	}
	return b.String()
}
