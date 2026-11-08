package endpoints

import (
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/goccy/go-yaml"
)

// Config 持有一组服务端点 URL，支持从 YAML 单字符串或字符串列表反序列化。
// 向后兼容：YAML 中写单个字符串等价于只配置一个端点。
type Config struct {
	urls []string
}

// UnmarshalYAML 实现 yaml.BytesUnmarshaler，接受 string 和 []string 两种格式。
func (c *Config) UnmarshalYAML(raw []byte) error {
	var s string
	if err := yaml.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if s != "" {
			c.urls = []string{s}
		}
		return nil
	}

	var arr []string
	if err := yaml.Unmarshal(raw, &arr); err != nil {
		return fmt.Errorf("endpoint must be a string or list of strings: %w", err)
	}
	for _, u := range arr {
		u = strings.TrimSpace(u)
		if u != "" {
			c.urls = append(c.urls, u)
		}
	}
	return nil
}

// New 创建一个包含给定 URL 的 Config。
// 用于在 Go 代码中构造端点列表（测试和内部使用）。
func New(urls ...string) Config {
	var result []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u != "" {
			result = append(result, u)
		}
	}
	return Config{urls: result}
}

// IsEmpty 报告是否没有配置任何端点。
func (c *Config) IsEmpty() bool {
	return len(c.urls) == 0
}

// Len 返回已配置的端点数量。
func (c *Config) Len() int {
	return len(c.urls)
}

// String 返回第一个端点，如果没有则返回空字符串。
// 用于需要单个 URL 的向后兼容场景。
func (c *Config) String() string {
	if len(c.urls) == 0 {
		return ""
	}
	return c.urls[0]
}

// All 返回所有已配置端点的副本。
func (c *Config) All() []string {
	result := make([]string, len(c.urls))
	copy(result, c.urls)
	return result
}

// NewPicker 创建一个 Picker 用于故障转移迭代。
// 每次创建 Picker 时会随机打乱端点顺序，实现随机优先 + 顺序故障转移。
func (c *Config) NewPicker() *Picker {
	if len(c.urls) == 0 {
		return &Picker{}
	}

	indices := make([]int, len(c.urls))
	for i := range indices {
		indices[i] = i
	}
	rand.Shuffle(len(indices), func(i, j int) {
		indices[i], indices[j] = indices[j], indices[i]
	})

	urls := make([]string, len(c.urls))
	copy(urls, c.urls)

	return &Picker{urls: urls, order: indices}
}

// Picker 提供端点的随机顺序迭代，用于故障转移。
// 首次调用 Next() 返回随机选择的端点，后续调用返回剩余端点。
type Picker struct {
	urls   []string
	order  []int
	cursor int
}

// Next 返回下一个端点及其在原始列表中的索引。
// 当所有端点都已遍历时返回 ("", -1, false)。
func (p *Picker) Next() (url string, index int, ok bool) {
	if p.cursor >= len(p.order) {
		return "", -1, false
	}
	idx := p.order[p.cursor]
	p.cursor++
	return p.urls[idx], idx, true
}
