package endpoints

import (
	"testing"

	"github.com/goccy/go-yaml"
)

func TestConfigUnmarshalString(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte(`"https://example.com"`), &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if c.Len() != 1 {
		t.Fatalf("expected 1 endpoint, got %d", c.Len())
	}
	if c.String() != "https://example.com" {
		t.Errorf("expected 'https://example.com', got %q", c.String())
	}
}

func TestConfigUnmarshalBareString(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte(`https://example.com`), &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if c.Len() != 1 {
		t.Fatalf("expected 1 endpoint, got %d", c.Len())
	}
}

func TestConfigUnmarshalList(t *testing.T) {
	var c Config
	input := `
- https://a.example.com
- https://b.example.com
- https://c.example.com
`
	if err := yaml.Unmarshal([]byte(input), &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if c.Len() != 3 {
		t.Fatalf("expected 3 endpoints, got %d", c.Len())
	}
	all := c.All()
	if all[0] != "https://a.example.com" {
		t.Errorf("first endpoint = %q, want %q", all[0], "https://a.example.com")
	}
}

func TestConfigUnmarshalInlineList(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte(`["https://a.com", "https://b.com"]`), &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if c.Len() != 2 {
		t.Fatalf("expected 2 endpoints, got %d", c.Len())
	}
}

func TestConfigUnmarshalEmptyString(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte(`""`), &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if !c.IsEmpty() {
		t.Error("empty string should result in empty config")
	}
}

func TestConfigUnmarshalEmptyList(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte(`[]`), &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if !c.IsEmpty() {
		t.Error("empty list should result in empty config")
	}
}

func TestConfigUnmarshalListWithBlanks(t *testing.T) {
	var c Config
	input := `
- https://a.example.com
- ""
- https://b.example.com
- "  "
`
	if err := yaml.Unmarshal([]byte(input), &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if c.Len() != 2 {
		t.Fatalf("expected 2 non-empty endpoints, got %d", c.Len())
	}
}

func TestConfigUnmarshalInvalid(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte(`key: value`), &c); err == nil {
		t.Error("expected error for mapping value")
	}
}

func TestConfigIsEmpty(t *testing.T) {
	var c Config
	if !c.IsEmpty() {
		t.Error("zero value should be empty")
	}
	c.urls = []string{"https://example.com"}
	if c.IsEmpty() {
		t.Error("non-empty urls should not be empty")
	}
}

func TestConfigAllReturnsCopy(t *testing.T) {
	c := Config{urls: []string{"a", "b"}}
	all := c.All()
	all[0] = "modified"
	if c.urls[0] != "a" {
		t.Error("All() should return a copy, modifying it should not affect original")
	}
}

func TestPickerSingleEndpoint(t *testing.T) {
	c := Config{urls: []string{"https://only.example.com"}}
	p := c.NewPicker()

	url, idx, ok := p.Next()
	if !ok || url != "https://only.example.com" || idx != 0 {
		t.Errorf("first Next() = (%q, %d, %v), want (%q, 0, true)", url, idx, ok, "https://only.example.com")
	}

	_, _, ok = p.Next()
	if ok {
		t.Error("second Next() should return ok=false")
	}
}

func TestPickerVisitsAllEndpoints(t *testing.T) {
	c := Config{urls: []string{"a", "b", "c", "d", "e"}}
	p := c.NewPicker()

	seen := make(map[string]bool)
	for {
		url, _, ok := p.Next()
		if !ok {
			break
		}
		if seen[url] {
			t.Errorf("endpoint %q visited twice", url)
		}
		seen[url] = true
	}

	if len(seen) != 5 {
		t.Errorf("visited %d endpoints, want 5", len(seen))
	}
}

func TestPickerEmptyConfig(t *testing.T) {
	c := Config{}
	p := c.NewPicker()

	_, _, ok := p.Next()
	if ok {
		t.Error("Next() on empty picker should return ok=false")
	}
}

func TestPickerRandomDistribution(t *testing.T) {
	c := Config{urls: []string{"a", "b", "c"}}
	firstCounts := make(map[string]int)
	const iterations = 300

	for i := 0; i < iterations; i++ {
		p := c.NewPicker()
		url, _, ok := p.Next()
		if !ok {
			t.Fatal("expected at least one endpoint")
		}
		firstCounts[url]++
	}

	// With 3 endpoints and 300 iterations, each should appear roughly 100 times.
	// We check that no single endpoint dominates (> 60% would indicate non-random).
	for _, count := range firstCounts {
		if count > iterations*60/100 {
			t.Errorf("endpoint appeared %d/%d times (>60%%), distribution seems non-random", count, iterations)
		}
	}

	// All 3 endpoints should have been picked as first at least once
	if len(firstCounts) != 3 {
		t.Errorf("expected all 3 endpoints to be first at least once, got %d", len(firstCounts))
	}
}

func TestConfigUnmarshalInStruct(t *testing.T) {
	type TestConfig struct {
		Endpoint Config `yaml:"endpoint"`
	}
	var tc TestConfig
	input := `
endpoint:
  - https://a.example.com
  - https://b.example.com
`
	if err := yaml.Unmarshal([]byte(input), &tc); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if tc.Endpoint.Len() != 2 {
		t.Fatalf("expected 2 endpoints, got %d", tc.Endpoint.Len())
	}
}

func TestConfigUnmarshalInStructSingle(t *testing.T) {
	type TestConfig struct {
		Endpoint Config `yaml:"endpoint"`
	}
	var tc TestConfig
	input := `endpoint: "https://single.example.com"`
	if err := yaml.Unmarshal([]byte(input), &tc); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if tc.Endpoint.Len() != 1 {
		t.Fatalf("expected 1 endpoint, got %d", tc.Endpoint.Len())
	}
	if tc.Endpoint.String() != "https://single.example.com" {
		t.Errorf("got %q", tc.Endpoint.String())
	}
}
