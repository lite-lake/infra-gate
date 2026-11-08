package auth

// JWT 签发/校验单测（内部PRD §13 关键用例）：
// 往返、过期拒绝、篡改签名拒绝、host 不匹配拒绝、key 随密码变化（改密后旧 token 失效）、
// 算法混淆拒绝、格式非法拒绝。

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var (
	testKey  = deriveKey("test-password")
	testNow  = time.Unix(1758758400, 0)
	testTTL  = 24 * time.Hour
	testHost = "demo.example.com"
)

func TestIssueAndVerifyRoundtrip(t *testing.T) {
	token := IssueToken(testKey, testHost, testNow, testTTL)
	if !VerifyToken(token, testKey, testHost, testNow.Add(time.Minute)) {
		t.Fatalf("freshly issued token should verify")
	}

	// payload 内容断言：host 绑定 + exp = iat + ttl
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if claims.Host != testHost {
		t.Errorf("claims.host = %q, want %q", claims.Host, testHost)
	}
	if claims.Iat != testNow.Unix() {
		t.Errorf("claims.iat = %d, want %d", claims.Iat, testNow.Unix())
	}
	if claims.Exp != testNow.Add(testTTL).Unix() {
		t.Errorf("claims.exp = %d, want %d", claims.Exp, testNow.Add(testTTL).Unix())
	}

	// header 断言：固定 HS256
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h jwtHeader
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if h.Alg != "HS256" || h.Typ != "JWT" {
		t.Errorf("header = %+v, want alg HS256 / typ JWT", h)
	}
}

func TestVerifyTokenExpired(t *testing.T) {
	token := IssueToken(testKey, testHost, testNow, testTTL)
	if VerifyToken(token, testKey, testHost, testNow.Add(testTTL)) {
		t.Errorf("token valid exactly at exp should be rejected")
	}
	if VerifyToken(token, testKey, testHost, testNow.Add(testTTL+time.Hour)) {
		t.Errorf("expired token should be rejected")
	}
}

func TestVerifyTokenTamperedSignature(t *testing.T) {
	token := IssueToken(testKey, testHost, testNow, testTTL)
	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sig[0] ^= 0xFF
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
	if VerifyToken(tampered, testKey, testHost, testNow) {
		t.Errorf("tampered signature should be rejected")
	}

	// 篡改 payload（换个 host）同样拒绝
	payload := base64.RawURLEncoding.EncodeToString(mustJSON(jwtClaims{
		Host: "evil.example.com", Iat: testNow.Unix(), Exp: testNow.Add(testTTL).Unix(),
	}))
	if VerifyToken(parts[0]+"."+payload+"."+parts[2], testKey, "evil.example.com", testNow) {
		t.Errorf("token with swapped payload should be rejected")
	}
}

func TestVerifyTokenHostMismatch(t *testing.T) {
	token := IssueToken(testKey, testHost, testNow, testTTL)
	if VerifyToken(token, testKey, "other.example.com", testNow) {
		t.Errorf("token bound to %q must not verify for another host", testHost)
	}
}

func TestKeyDerivedFromPassword_ChangePasswordInvalidatesTokens(t *testing.T) {
	oldKey := deriveKey("old-password")
	newKey := deriveKey("new-password")
	token := IssueToken(oldKey, testHost, testNow, testTTL)
	if VerifyToken(token, newKey, testHost, testNow) {
		t.Errorf("token signed with old password's key must fail after password change")
	}
	if !VerifyToken(token, deriveKey("old-password"), testHost, testNow) {
		t.Errorf("sanity: token should still verify with unchanged key")
	}
}

func TestVerifyTokenMalformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-jwt",
		"a.b",
		"a.b.c.d",
		"@@@.@@@.@@@",
	}
	for _, tc := range cases {
		if VerifyToken(tc, testKey, testHost, testNow) {
			t.Errorf("malformed token %q should be rejected", tc)
		}
	}
}

func TestVerifyTokenWrongAlgHeader(t *testing.T) {
	// alg 混淆（none）：即便构造出合法结构也必须拒绝
	header := base64.RawURLEncoding.EncodeToString(mustJSON(jwtHeader{Alg: "none", Typ: "JWT"}))
	payload := base64.RawURLEncoding.EncodeToString(mustJSON(jwtClaims{
		Host: testHost, Iat: testNow.Unix(), Exp: testNow.Add(testTTL).Unix(),
	}))
	token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(nilSig())
	if VerifyToken(token, testKey, testHost, testNow) {
		t.Errorf("alg=none token should be rejected")
	}
}

func nilSig() []byte { return []byte{} }

// ── M3 KDF v2 单测（内部PRD §5/§11.4，决策 D4/D7，出口标准②）──

// scrypt 参数写死常量断言（决策 D7：参数不进配置，防误配弱化；N=2^15 内存困难）
func TestDeriveKeyV2ScryptParams(t *testing.T) {
	if AuthKeyDerivationPrefixV2 != "litelake-gate-auth:v2:" {
		t.Errorf("AuthKeyDerivationPrefixV2 = %q, want litelake-gate-auth:v2:", AuthKeyDerivationPrefixV2)
	}
	if scryptN != 32768 {
		t.Errorf("scryptN = %d, want 32768 (N=2^15)", scryptN)
	}
	if scryptR != 8 {
		t.Errorf("scryptR = %d, want 8", scryptR)
	}
	if scryptP != 1 {
		t.Errorf("scryptP = %d, want 1", scryptP)
	}
	if scryptKeyLen != 32 {
		t.Errorf("scryptKeyLen = %d, want 32 (HMAC-SHA256 key length)", scryptKeyLen)
	}
}

// 同密码两次派生等值（确定性，跨进程/跨重启稳定 → 重启后已发 token 仍有效），
// 且与 v1 派生密钥不同（域分隔生效，v2 换代不是同值改名）
func TestDeriveKeyDeterministic(t *testing.T) {
	k1 := deriveKey("same-password")
	k2 := deriveKey("same-password")
	if len(k1) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(k1))
	}
	if string(k1) != string(k2) {
		t.Errorf("two derivations of the same password must be identical (KDF determinism)")
	}

	// 对照组：v1 派生密钥 = SHA-256(v1 前缀 + 密码)，与 v2 派生不同
	v1sum := sha256.Sum256([]byte(AuthKeyDerivationPrefix + "same-password"))
	if string(k1) == string(v1sum[:]) {
		t.Errorf("v2 derivation must differ from legacy v1 SHA-256 derivation")
	}
}

// v1 旧 token 升级后一次性失效（决策 D4）：v1 派生密钥签发的存量 token，
// 用 v2 派生密钥校验必须失败——用户重输密码换取离线爆破防线
func TestV1TokenInvalidAfterUpgrade(t *testing.T) {
	// 以 v1 口径构造"存量"token（升级前签发）
	v1sum := sha256.Sum256([]byte(AuthKeyDerivationPrefix + testPassword))
	v1Token := IssueToken(v1sum[:], testHost, testNow, testTTL)

	// 升级后校验侧只认 v2 派生密钥：v1 token 一律拒绝
	if VerifyToken(v1Token, deriveKey(testPassword), testHost, testNow) {
		t.Errorf("legacy v1 token must be rejected after KDF v2 upgrade (D4)")
	}

	// 对照：同密码 v2 新 token 正常校验（无版本协商旁路）
	v2Token := IssueToken(deriveKey(testPassword), testHost, testNow, testTTL)
	if !VerifyToken(v2Token, deriveKey(testPassword), testHost, testNow) {
		t.Errorf("fresh v2 token should verify")
	}
}

// 错误密码派生的密钥无法校验 token（KDF 输入敏感性的端到端体现）
func TestTokenWrongPasswordKeyFails(t *testing.T) {
	token := IssueToken(deriveKey("correct-horse"), testHost, testNow, testTTL)
	if VerifyToken(token, deriveKey("wrong-battery"), testHost, testNow) {
		t.Errorf("token signed with one password's key must not verify with another's")
	}
}
