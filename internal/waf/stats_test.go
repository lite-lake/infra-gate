package waf

import (
	"testing"
	"time"
)

func TestStatsTrackerRecordBlock(t *testing.T) {
	st := newStatsTracker()

	st.recordRequest("host1")
	st.recordRequest("host1")
	st.recordRequest("host2")
	st.recordBlock("host1", "1.2.3.4", "GET", "/test")
	st.recordBlock("host1", "1.2.3.4", "POST", "/test2")
	st.recordBlock("host2", "5.6.7.8", "GET", "/other")

	snap := st.snapshot()
	if snap.TotalBlocked != 3 {
		t.Errorf("TotalBlocked = %d, want 3", snap.TotalBlocked)
	}
	if snap.TotalRequests != 3 {
		t.Errorf("TotalRequests = %d, want 3", snap.TotalRequests)
	}
	if snap.TotalPassed != 0 {
		t.Errorf("TotalPassed = %d, want 0 (3 requests - 3 blocks)", snap.TotalPassed)
	}

	// Check host breakdown
	hostStats := map[string]HostStats{}
	for _, hs := range snap.BlocksByHost {
		hostStats[hs.HostName] = hs
	}
	if hostStats["host1"].TotalBlocked != 2 {
		t.Errorf("host1 blocked = %d, want 2", hostStats["host1"].TotalBlocked)
	}
	if hostStats["host1"].TotalRequests != 2 {
		t.Errorf("host1 requests = %d, want 2", hostStats["host1"].TotalRequests)
	}
	if hostStats["host2"].TotalBlocked != 1 {
		t.Errorf("host2 blocked = %d, want 1", hostStats["host2"].TotalBlocked)
	}
	if hostStats["host2"].TotalRequests != 1 {
		t.Errorf("host2 requests = %d, want 1", hostStats["host2"].TotalRequests)
	}

	// Check last block info
	if snap.LastBlockIP != "5.6.7.8" {
		t.Errorf("LastBlockIP = %q, want 5.6.7.8", snap.LastBlockIP)
	}
	if snap.LastBlockPath != "/other" {
		t.Errorf("LastBlockPath = %q, want /other", snap.LastBlockPath)
	}
}

func TestStatsTrackerRecordDetect(t *testing.T) {
	st := newStatsTracker()

	st.recordRequest("host1")
	st.recordRequest("host1")
	st.recordDetect("host1", "1.2.3.4", "GET", "/?id=1' OR 1=1")
	st.recordDetect("host1", "5.6.7.8", "POST", "/login")

	snap := st.snapshot()
	if snap.TotalDetected != 2 {
		t.Errorf("TotalDetected = %d, want 2", snap.TotalDetected)
	}
	if snap.TotalRequests != 2 {
		t.Errorf("TotalRequests = %d, want 2", snap.TotalRequests)
	}
	if snap.TotalBlocked != 0 {
		t.Errorf("TotalBlocked = %d, want 0", snap.TotalBlocked)
	}
	if snap.TotalPassed != 0 {
		t.Errorf("TotalPassed = %d, want 0 (2 requests - 2 detects - 0 blocks)", snap.TotalPassed)
	}

	// Check last detect info
	if snap.LastDetectIP != "5.6.7.8" {
		t.Errorf("LastDetectIP = %q, want 5.6.7.8", snap.LastDetectIP)
	}
	if snap.LastDetectPath != "/login" {
		t.Errorf("LastDetectPath = %q, want /login", snap.LastDetectPath)
	}
	if snap.LastDetectTime == nil {
		t.Error("LastDetectTime should not be nil")
	}
}

func TestStatsTrackerMixedBlockAndDetect(t *testing.T) {
	st := newStatsTracker()

	// 10 requests total, 2 detected, 3 blocked, 5 passed cleanly
	for i := 0; i < 10; i++ {
		st.recordRequest("host1")
	}
	st.recordDetect("host1", "1.2.3.4", "GET", "/detect1")
	st.recordDetect("host1", "5.6.7.8", "GET", "/detect2")
	st.recordBlock("host1", "9.0.0.1", "GET", "/block1")
	st.recordBlock("host1", "9.0.0.2", "GET", "/block2")
	st.recordBlock("host1", "9.0.0.3", "GET", "/block3")

	snap := st.snapshot()
	if snap.TotalRequests != 10 {
		t.Errorf("TotalRequests = %d, want 10", snap.TotalRequests)
	}
	if snap.TotalDetected != 2 {
		t.Errorf("TotalDetected = %d, want 2", snap.TotalDetected)
	}
	if snap.TotalBlocked != 3 {
		t.Errorf("TotalBlocked = %d, want 3", snap.TotalBlocked)
	}
	if snap.TotalPassed != 5 {
		t.Errorf("TotalPassed = %d, want 5 (10 - 3 blocks - 2 detects)", snap.TotalPassed)
	}
}

func TestStatsTrackerUpdateLastBlockRule(t *testing.T) {
	st := newStatsTracker()

	detail := RuleMatchDetail{
		RuleID:  942100,
		Message: "SQL Injection detected",
	}
	st.recordBlock("host1", "1.2.3.4", "GET", "/?id=1' OR 1=1")
	st.updateLastBlockRule(detail)

	snap := st.snapshot()
	if snap.LastBlockRuleID != 942100 {
		t.Errorf("LastBlockRuleID = %d, want 942100", snap.LastBlockRuleID)
	}
	if snap.LastBlockMsg != "SQL Injection detected" {
		t.Errorf("LastBlockMsg = %q, want 'SQL Injection detected'", snap.LastBlockMsg)
	}
}

func TestStatsTrackerRecentEvents(t *testing.T) {
	st := newStatsTracker()

	// No events
	events := st.recentEvents(10)
	if len(events) != 0 {
		t.Errorf("Expected 0 events, got %d", len(events))
	}

	// Add some block events
	for i := 0; i < 3; i++ {
		st.recordBlock("host1", "1.2.3.4", "GET", "/test")
		st.recordEvent(WAFEvent{
			Time:     time.Now(),
			Type:     EventTypeBlock,
			ClientIP: "1.2.3.4",
			Method:   "GET",
			Path:     "/test",
			RuleID:   1000 + i,
		})
	}

	// Add some detect events
	for i := 0; i < 2; i++ {
		st.recordDetect("host1", "5.6.7.8", "POST", "/detect")
		st.recordEvent(WAFEvent{
			Time:     time.Now(),
			Type:     EventTypeDetect,
			ClientIP: "5.6.7.8",
			Method:   "POST",
			Path:     "/detect",
			RuleID:   2000 + i,
		})
	}

	events = st.recentEvents(3)
	if len(events) != 3 {
		t.Errorf("Expected 3 events, got %d", len(events))
	}
	// Should return the most recent 3 (last 3 of the 5)
	if events[0].RuleID != 1002 {
		t.Errorf("First event RuleID = %d, want 1002", events[0].RuleID)
	}
	if events[2].RuleID != 2001 {
		t.Errorf("Last event RuleID = %d, want 2001", events[2].RuleID)
	}

	// Verify event types
	if events[0].Type != EventTypeBlock {
		t.Errorf("First event Type = %q, want %q", events[0].Type, EventTypeBlock)
	}
	if events[2].Type != EventTypeDetect {
		t.Errorf("Last event Type = %q, want %q", events[2].Type, EventTypeDetect)
	}
}

func TestStatsTrackerRingBufferOverflow(t *testing.T) {
	st := newStatsTracker()

	// Add more than maxEvents
	for i := 0; i < maxEvents+50; i++ {
		st.recordEvent(WAFEvent{
			Time:     time.Now(),
			Type:     EventTypeBlock,
			ClientIP: "1.2.3.4",
			Method:   "GET",
			Path:     "/test",
			RuleID:   i,
		})
	}

	events := st.recentEvents(0) // 0 means all
	if len(events) != maxEvents {
		t.Errorf("Expected %d events, got %d", maxEvents, len(events))
	}

	// Verify that recentEvents returns the LATEST events, not the oldest
	lastEvent := events[len(events)-1]
	if lastEvent.RuleID != maxEvents+49 {
		t.Errorf("Last event RuleID = %d, want %d (latest event)", lastEvent.RuleID, maxEvents+49)
	}

	// Verify that requesting a subset returns the most recent ones
	recent5 := st.recentEvents(5)
	if len(recent5) != 5 {
		t.Fatalf("Expected 5 events, got %d", len(recent5))
	}
	expectedStart := maxEvents + 45
	if recent5[0].RuleID != expectedStart {
		t.Errorf("First recent event RuleID = %d, want %d", recent5[0].RuleID, expectedStart)
	}
	if recent5[4].RuleID != maxEvents+49 {
		t.Errorf("Last recent event RuleID = %d, want %d", recent5[4].RuleID, maxEvents+49)
	}
}

func TestStatsSnapshotEmpty(t *testing.T) {
	st := newStatsTracker()
	snap := st.snapshot()

	if snap.TotalBlocked != 0 {
		t.Errorf("Empty tracker TotalBlocked = %d, want 0", snap.TotalBlocked)
	}
	if snap.TotalRequests != 0 {
		t.Errorf("Empty tracker TotalRequests = %d, want 0", snap.TotalRequests)
	}
	if snap.TotalDetected != 0 {
		t.Errorf("Empty tracker TotalDetected = %d, want 0", snap.TotalDetected)
	}
	if snap.TotalPassed != 0 {
		t.Errorf("Empty tracker TotalPassed = %d, want 0", snap.TotalPassed)
	}
	if snap.LastBlockTime != nil {
		t.Error("Empty tracker should have nil LastBlockTime")
	}
	if snap.LastDetectTime != nil {
		t.Error("Empty tracker should have nil LastDetectTime")
	}
}

func TestStatsTrackerNextEventID(t *testing.T) {
	st := newStatsTracker()

	id1 := st.nextEventID()
	id2 := st.nextEventID()
	id3 := st.nextEventID()

	if id1 == id2 || id2 == id3 || id1 == id3 {
		t.Error("Event IDs should be unique")
	}
}

func TestStatsTrackerEventIDUniquenessAcrossInstances(t *testing.T) {
	st1 := newStatsTracker()
	st2 := newStatsTracker()

	// Even if both trackers generate the same sequence number,
	// the instanceID hash in the high bits should make IDs unique
	id1 := st1.nextEventID()
	id2 := st2.nextEventID()

	if id1 == id2 {
		t.Error("Event IDs from different instances should be unique")
	}
}

func TestStatsTrackerFindEvent(t *testing.T) {
	st := newStatsTracker()

	// No events
	_, found := st.findEvent(1)
	if found {
		t.Error("findEvent should return false when no events")
	}

	// Add events
	ev1 := WAFEvent{ID: st.nextEventID(), Type: EventTypeBlock, RuleID: 100}
	ev2 := WAFEvent{ID: st.nextEventID(), Type: EventTypeDetect, RuleID: 200}
	st.recordEvent(ev1)
	st.recordEvent(ev2)

	// Find existing
	result, found := st.findEvent(ev1.ID)
	if !found {
		t.Error("findEvent(ev1.ID) should return true")
	}
	if result.RuleID != 100 {
		t.Errorf("findEvent(ev1.ID).RuleID = %d, want 100", result.RuleID)
	}

	result, found = st.findEvent(ev2.ID)
	if !found {
		t.Error("findEvent(ev2.ID) should return true")
	}
	if result.RuleID != 200 {
		t.Errorf("findEvent(ev2.ID).RuleID = %d, want 200", result.RuleID)
	}

	// Find non-existing
	_, found = st.findEvent(999999)
	if found {
		t.Error("findEvent(999999) should return false")
	}
}

func TestTruncateString(t *testing.T) {
	// Short string unchanged
	result := truncateString("hello", 10)
	if result != "hello" {
		t.Errorf("truncateString('hello', 10) = %q, want 'hello'", result)
	}

	// Exact length unchanged
	result = truncateString("hello", 5)
	if result != "hello" {
		t.Errorf("truncateString('hello', 5) = %q, want 'hello'", result)
	}

	// Truncated ASCII
	result = truncateString("hello world", 5)
	if result != "hello" {
		t.Errorf("truncateString('hello world', 5) = %q, want 'hello'", result)
	}

	// Truncated multi-byte UTF-8 should not produce invalid sequences
	result = truncateString("你好世界测试", 6)
	if !isValidUTF8(result) {
		t.Errorf("truncateString produced invalid UTF-8: %q", result)
	}

	// Edge cases
	if truncateString("hello", 0) != "" {
		t.Error("truncateString with max=0 should return empty string")
	}
	if truncateString("hello", -1) != "" {
		t.Error("truncateString with negative max should return empty string")
	}
}

// TestTruncateStringLargeInput ensures truncation of very large strings completes
// in bounded time (O(1) relative to input size). This is a regression test for
// the sustained 100% CPU bug where the old O(n^2) implementation could peg a
// core for hours/days when WAF ErrorCallback passed multi-MB matched values.
func TestTruncateStringLargeInput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large input test in short mode")
	}
	// 128MB simulates coraza's default RequestBodyLimit (134217728 bytes).
	// A WAF rule match on a large request body would pass this size to truncateString.
	sizes := []int{1 << 20, 10 << 20, 128 << 20}
	for _, size := range sizes {
		s := make([]byte, size)
		for i := range s {
			s[i] = 'A'
		}
		result := truncateString(string(s), maxValueLen)
		if len(result) > maxValueLen {
			t.Errorf("truncateString(%d bytes, %d) returned %d bytes, want <= %d",
				size, maxValueLen, len(result), maxValueLen)
		}
		if len(result) == 0 {
			t.Errorf("truncateString(%d bytes, %d) returned empty string", size, maxValueLen)
		}
	}
}

// TestTruncateStringMultibyteBoundary ensures truncation respects UTF-8 rune
// boundaries and never produces invalid UTF-8, matching the original behavior.
func TestTruncateStringMultibyteBoundary(t *testing.T) {
	// 4-byte rune: 𝕄 (U+1D544)
	s := "ab𝕄cd"
	// Truncate at byte 3: should include "ab" and NOT the first byte of 𝕄
	result := truncateString(s, 3)
	if !isValidUTF8(result) {
		t.Errorf("truncateString produced invalid UTF-8: %q", result)
	}
	if result != "ab" {
		t.Errorf("truncateString(%q, 3) = %q, want %q", s, result, "ab")
	}
	// Truncate at byte 5: should include "ab𝕄" (2 + 3 = 5 bytes, but 𝕄 is 4 bytes)
	// "ab" = 2 bytes, "𝕄" = 4 bytes, total 6 bytes. Truncating at 5 backs up to 2.
	result = truncateString(s, 5)
	if !isValidUTF8(result) {
		t.Errorf("truncateString produced invalid UTF-8: %q", result)
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == 0xFFFD {
			return false
		}
	}
	return true
}

func TestGenerateInstanceID(t *testing.T) {
	id1 := generateInstanceID()
	id2 := generateInstanceID()

	if len(id1) != instanceIDLen {
		t.Errorf("instance ID length = %d, want %d", len(id1), instanceIDLen)
	}
	// Verify all characters are from the charset
	for _, c := range id1 {
		found := false
		for _, valid := range instanceIDCharset {
			if c == valid {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("instance ID contains invalid character: %c", c)
		}
	}
	// Two IDs should almost certainly be different (probability of collision is ~1/62^8)
	if id1 == id2 {
		t.Error("Two randomly generated instance IDs should not be equal")
	}
}
