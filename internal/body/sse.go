package body

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// StreamEvent is one event from an SSE or NDJSON stream.
type StreamEvent struct {
	Event string `json:"event,omitempty"`
	ID    string `json:"id,omitempty"`
	Data  any    `json:"data,omitempty"`
}

// StreamInfo summarises a Server-Sent Events (text/event-stream) or NDJSON
// stream, preserving both the beginning and the end (where errors, finish
// reasons and token usage appear) and assembling common LLM token deltas.
type StreamInfo struct {
	Format     string           `json:"format"` // "sse" or "ndjson"
	Events     int              `json:"events"`
	TTFTMs     float64          `json:"ttft_ms,omitempty"`
	Model      string           `json:"model,omitempty"`
	Assembled  string           `json:"assembled,omitempty"`
	ToolCalls  []string         `json:"tool_calls,omitempty"`
	StopReason string           `json:"stop_reason,omitempty"`
	Usage      map[string]int64 `json:"usage,omitempty"`
	Error      string           `json:"error,omitempty"`
	Head       []StreamEvent    `json:"head,omitempty"`
	Tail       []StreamEvent    `json:"tail,omitempty"`
	Omitted    int              `json:"omitted,omitempty"`
}

// IsSSE reports whether ct is Server-Sent Events.
func IsSSE(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	media, _, _ := strings.Cut(ct, ";")
	return strings.TrimSpace(media) == "text/event-stream"
}

// IsNDJSON reports whether ct is newline-delimited JSON.
func IsNDJSON(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	media, _, _ := strings.Cut(ct, ";")
	switch strings.TrimSpace(media) {
	case "application/x-ndjson", "application/ndjson", "application/jsonl", "application/jsonlines", "application/json-seq":
		return true
	}
	return false
}

// DecodeSSE parses a text/event-stream body into a structured StreamInfo.
func DecodeSSE(data []byte, budget int) *StreamInfo {
	norm := strings.ReplaceAll(string(data), "\r\n", "\n")
	blocks := strings.Split(norm, "\n\n")
	var rawEvents []StreamEvent
	for _, blk := range blocks {
		blk = strings.Trim(blk, "\n")
		if blk == "" {
			continue
		}
		var evName, evID string
		var dataLines []string
		hasField := false
		for _, line := range strings.Split(blk, "\n") {
			if line == "" || strings.HasPrefix(line, ":") {
				continue
			}
			field, val, hasColon := strings.Cut(line, ":")
			if hasColon && strings.HasPrefix(val, " ") {
				val = val[1:]
			}
			switch field {
			case "event":
				evName = val
				hasField = true
			case "id":
				evID = val
				hasField = true
			case "data":
				dataLines = append(dataLines, val)
				hasField = true
			}
		}
		if !hasField {
			continue
		}
		payload := strings.Join(dataLines, "\n")
		if strings.TrimSpace(payload) == "[DONE]" && evName == "" {
			continue
		}
		ev := StreamEvent{Event: evName, ID: evID}
		if v, err := ParseJSON([]byte(payload)); err == nil {
			ev.Data = v
		} else if payload != "" {
			ev.Data = payload
		}
		rawEvents = append(rawEvents, ev)
	}
	return buildStreamInfo("sse", rawEvents, budget)
}

// DecodeNDJSON parses a newline-delimited JSON stream into a StreamInfo.
func DecodeNDJSON(data []byte, budget int) *StreamInfo {
	lines := bytes.Split(data, []byte{'\n'})
	var rawEvents []StreamEvent
	for _, l := range lines {
		l = bytes.TrimSpace(bytes.TrimLeft(l, "\x1e")) // RFC 7464 RS prefix
		if len(l) == 0 {
			continue
		}
		v, err := ParseJSON(l)
		if err != nil {
			// A stream that is not valid JSON per line is not NDJSON.
			if len(rawEvents) == 0 {
				return nil
			}
			rawEvents = append(rawEvents, StreamEvent{Data: string(l)})
			continue
		}
		rawEvents = append(rawEvents, StreamEvent{Data: v})
	}
	if len(rawEvents) == 0 {
		return nil
	}
	return buildStreamInfo("ndjson", rawEvents, budget)
}

func buildStreamInfo(format string, events []StreamEvent, budget int) *StreamInfo {
	info := &StreamInfo{Format: format, Events: len(events)}
	if len(events) == 0 {
		return info
	}
	var assembled strings.Builder
	seenTools := map[string]bool{}
	addTool := func(name string) {
		if name != "" && !seenTools[name] {
			seenTools[name] = true
			info.ToolCalls = append(info.ToolCalls, name)
		}
	}
	addUsage := func(k string, n int64) {
		if n <= 0 {
			return
		}
		if info.Usage == nil {
			info.Usage = map[string]int64{}
		}
		info.Usage[k] = n
	}

	var errEvents []StreamEvent
	for _, ev := range events {
		isErr := strings.EqualFold(ev.Event, "error")
		if obj, ok := ev.Data.(Object); ok {
			extractLLMFields(obj, info, &assembled, addTool, addUsage)
			if typ := objStr(obj, "type"); typ == "error" {
				isErr = true
			}
			if eVal, hasErr := obj.Get("error"); hasErr && eVal != nil && eVal != false {
				isErr = true
			}
			if isErr && info.Error == "" {
				if h := ErrorHint(obj); h != "" {
					info.Error = h
				} else if r := objStr(obj, "reason"); r != "" {
					info.Error = clip(r)
				} else if b, err := json.Marshal(obj); err == nil && len(b) > 0 && string(b) != "{}" {
					info.Error = clip(string(b))
				}
			}
		} else if isErr && info.Error == "" {
			if s, ok := ev.Data.(string); ok && s != "" {
				info.Error = clip(s)
			} else if ev.Data != nil {
				if b, err := json.Marshal(ev.Data); err == nil && len(b) > 0 {
					info.Error = clip(string(b))
				}
			}
		}
		if isErr {
			if info.Error == "" {
				if ev.Event != "" {
					info.Error = clip(ev.Event)
				} else {
					info.Error = "stream error"
				}
			}
			errEvents = append(errEvents, ev)
		}
	}

	if assembled.Len() > 0 {
		s := assembled.String()
		if budget > 0 && len(s) > budget {
			s = clipUTF8(s, budget) + fmt.Sprintf("…(+%d bytes)", assembled.Len()-len(s))
		}
		info.Assembled = s
	}

	// Head + Tail + Error-frame windowing: never drop the tail or error frames.
	perBudget := max(budget/6, 160)
	shrinkEv := func(e StreamEvent) StreamEvent {
		out := StreamEvent{Event: e.Event, ID: e.ID}
		switch d := e.Data.(type) {
		case string:
			if len(d) > perBudget {
				out.Data = clipUTF8(d, perBudget) + "…"
			} else {
				out.Data = d
			}
		case nil:
		default:
			v, _ := TruncateJSON(d, perBudget)
			out.Data = v
		}
		return out
	}

	const headMax, tailMax = 2, 2
	if len(events) <= headMax+tailMax+1 {
		for _, e := range events {
			info.Head = append(info.Head, shrinkEv(e))
		}
		return info
	}
	for _, e := range events[:headMax] {
		info.Head = append(info.Head, shrinkEv(e))
	}
	tailStart := len(events) - tailMax
	for _, e := range errEvents {
		// Ensure mid-stream error events appear in Tail if they happened before tailStart.
		inTail := false
		for _, te := range events[tailStart:] {
			if te.Event == e.Event && fmt.Sprint(te.Data) == fmt.Sprint(e.Data) {
				inTail = true
				break
			}
		}
		if !inTail && len(info.Tail) < 2 {
			info.Tail = append(info.Tail, shrinkEv(e))
		}
	}
	for _, e := range events[tailStart:] {
		info.Tail = append(info.Tail, shrinkEv(e))
	}
	info.Omitted = len(events) - headMax - tailMax
	return info
}

// extractLLMFields extracts model, text deltas, tool calls, finish reason and
// usage across OpenAI (Chat & Responses), Anthropic Messages, and Gemini SSE payloads.
func extractLLMFields(obj Object, info *StreamInfo, assembled *strings.Builder, addTool func(string), addUsage func(string, int64)) {
	if info.Model == "" {
		if m := objStr(obj, "model"); m != "" {
			info.Model = m
		} else if m := objStr(obj, "modelVersion"); m != "" {
			info.Model = m
		}
	}
	// Anthropic message_start: {"message": {"model": ..., "usage": ...}}
	if msg, ok := objObj(obj, "message"); ok {
		if info.Model == "" {
			info.Model = objStr(msg, "model")
		}
		if u, ok := objObj(msg, "usage"); ok {
			extractUsageObj(u, addUsage)
		}
	}
	// Anthropic content_block_start: {"content_block": {"type": "tool_use", "name": ...}}
	if cb, ok := objObj(obj, "content_block"); ok && objStr(cb, "type") == "tool_use" {
		addTool(objStr(cb, "name"))
	}
	// Anthropic content_block_delta / message_delta & OpenAI Responses delta
	if typ := objStr(obj, "type"); typ == "response.output_text.delta" {
		assembled.WriteString(objStr(obj, "delta"))
	}
	if item, ok := objObj(obj, "item"); ok && objStr(item, "type") == "function_call" {
		addTool(objStr(item, "name"))
	}
	if delta, ok := objObj(obj, "delta"); ok {
		if t := objStr(delta, "text"); t != "" {
			assembled.WriteString(t)
		}
		if sr := objStr(delta, "stop_reason"); sr != "" {
			info.StopReason = sr
		}
	}
	// OpenAI Chat Completions: choices[0].delta.{content, tool_calls}, finish_reason
	if choices, ok := objArr(obj, "choices"); ok && len(choices) > 0 {
		if c0, ok := choices[0].(Object); ok {
			if sr := objStr(c0, "finish_reason"); sr != "" {
				info.StopReason = sr
			}
			if d, ok := objObj(c0, "delta"); ok {
				assembled.WriteString(objStr(d, "content"))
				if tcs, ok := objArr(d, "tool_calls"); ok {
					for _, tc := range tcs {
						if tco, ok := tc.(Object); ok {
							if fn, ok := objObj(tco, "function"); ok {
								addTool(objStr(fn, "name"))
							}
						}
					}
				}
			}
		}
	}
	// Google Gemini: candidates[0].content.parts[].{text, functionCall}, finishReason
	if cands, ok := objArr(obj, "candidates"); ok && len(cands) > 0 {
		if c0, ok := cands[0].(Object); ok {
			if sr := objStr(c0, "finishReason"); sr != "" {
				info.StopReason = sr
			}
			if content, ok := objObj(c0, "content"); ok {
				if parts, ok := objArr(content, "parts"); ok {
					for _, p := range parts {
						if po, ok := p.(Object); ok {
							assembled.WriteString(objStr(po, "text"))
							if fc, ok := objObj(po, "functionCall"); ok {
								addTool(objStr(fc, "name"))
							}
						}
					}
				}
			}
		}
	}
	// Usage objects (OpenAI, Anthropic, Responses, Gemini)
	if u, ok := objObj(obj, "usage"); ok {
		extractUsageObj(u, addUsage)
	}
	if resp, ok := objObj(obj, "response"); ok {
		if info.Model == "" {
			info.Model = objStr(resp, "model")
		}
		if u, ok := objObj(resp, "usage"); ok {
			extractUsageObj(u, addUsage)
		}
	}
	if um, ok := objObj(obj, "usageMetadata"); ok {
		extractUsageObj(um, addUsage)
	}
}

func extractUsageObj(u Object, addUsage func(string, int64)) {
	for _, pair := range [][2]string{
		{"input_tokens", "input_tokens"},
		{"prompt_tokens", "input_tokens"},
		{"promptTokenCount", "input_tokens"},
		{"output_tokens", "output_tokens"},
		{"completion_tokens", "output_tokens"},
		{"candidatesTokenCount", "output_tokens"},
		{"total_tokens", "total_tokens"},
		{"totalTokenCount", "total_tokens"},
	} {
		if v, ok := u.Get(pair[0]); ok {
			if n, ok := jsonInt(v); ok {
				addUsage(pair[1], n)
			}
		}
	}
}

func objStr(o Object, k string) string {
	v, ok := o.Get(k)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func objObj(o Object, k string) (Object, bool) {
	v, ok := o.Get(k)
	if !ok {
		return nil, false
	}
	sub, ok := v.(Object)
	return sub, ok
}

func objArr(o Object, k string) ([]any, bool) {
	v, ok := o.Get(k)
	if !ok {
		return nil, false
	}
	arr, ok := v.([]any)
	return arr, ok
}

func jsonInt(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case float64:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

func clipUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// FormatStreamText renders a StreamInfo concisely for text output and TUI.
func FormatStreamText(s *StreamInfo) string {
	if s == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[%s: %d events", strings.ToUpper(s.Format), s.Events)
	if s.TTFTMs > 0 {
		fmt.Fprintf(&b, ", ttft %.0fms", s.TTFTMs)
	}
	if s.Model != "" {
		fmt.Fprintf(&b, ", model=%s", s.Model)
	}
	if s.StopReason != "" {
		fmt.Fprintf(&b, ", stop=%s", s.StopReason)
	}
	if len(s.Usage) > 0 {
		in, out := s.Usage["input_tokens"], s.Usage["output_tokens"]
		if in > 0 || out > 0 {
			fmt.Fprintf(&b, ", tokens=%d→%d", in, out)
		} else if tot := s.Usage["total_tokens"]; tot > 0 {
			fmt.Fprintf(&b, ", tokens=%d", tot)
		}
	}
	b.WriteByte(']')
	if s.Error != "" {
		fmt.Fprintf(&b, "\nERROR: %s", s.Error)
	}
	if len(s.ToolCalls) > 0 {
		fmt.Fprintf(&b, "\nTool calls: %s", strings.Join(s.ToolCalls, ", "))
	}
	if s.Assembled != "" {
		fmt.Fprintf(&b, "\nAssembled:\n  %s", strings.ReplaceAll(s.Assembled, "\n", "\n  "))
	}
	writeEv := func(e StreamEvent) {
		label := e.Event
		if label == "" {
			label = "data"
		}
		d, _ := marshalNoEscape(e.Data)
		fmt.Fprintf(&b, "\n  %s: %s", label, string(d))
	}
	if len(s.Head) > 0 && s.Assembled == "" {
		for _, e := range s.Head {
			writeEv(e)
		}
		if s.Omitted > 0 {
			fmt.Fprintf(&b, "\n  … (%d events omitted)", s.Omitted)
		}
		for _, e := range s.Tail {
			writeEv(e)
		}
	} else if len(s.Tail) > 0 && s.Error != "" {
		for _, e := range s.Tail {
			writeEv(e)
		}
	}
	return b.String()
}
