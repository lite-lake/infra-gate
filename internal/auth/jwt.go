package auth

// HS256 JWT 最小自实现（内部PRD §10）：仅实现本特性需要的签发与校验，
// 不引入 golang-jwt 等外部依赖，维持 gate 单二进制少依赖风格。签名校验用
// hmac.Equal（常数时间）。
//
// Token 形态（PRD §5.3）：
//
//	Header  : {"alg":"HS256","typ":"JWT"}
//	Payload : {"host":"<HostConfig.Name>","iat":<unix>,"exp":<unix>}
//	签名    : HMAC-SHA256(header.payload, key)
//
// key 由该 host 密码经慢哈希 KDF 派生（deriveKey，M3/scrypt v2）：改密码 = key 变 =
// 该 host 全部旧 JWT 立即失效，免费获得会话吊销（PRD §8.2）；内存困难型慢哈希使
// cookie 离线爆破代价从 SHA-256 的 ~10^10 次/秒量级降到 ~10 次/秒/核量级。

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

// AuthKeyDerivationPrefix V1 HMAC key 派生域分隔（已废弃，M3/内部PRD 决策 D4）：
// 升级后 v1 派生密钥不再被校验侧接受——存量 v1 token 一次性失效，用户重输密码。
// 常量仅为测试与历史对照保留，业务代码不得引用。
const AuthKeyDerivationPrefix = "litelake-gate-auth:v1:"

// AuthKeyDerivationPrefixV2 V2 KDF 域分隔前缀（M3，内部PRD §5/决策 D4）：
// 作为 scrypt 的 salt（域分隔兼 pepper——固定字节做 salt 不破坏确定性、跨重启稳定，
// 同时把「为其他系统爆破同一密码」的预计算分离出去）。密码本身不落日志。
const AuthKeyDerivationPrefixV2 = "litelake-gate-auth:v2:"

// scrypt 参数（M3/决策 D7：写死常量不进配置，防误配弱化；N=2^15 ≈ 32MB 内存/32 字节
// 派生，单次 ~100ms 量级，登录路径可接受）
const (
	// scryptN 内存/成本参数（2^15），必须为 2 的幂
	scryptN = 32768
	// scryptR 块大小
	scryptR = 8
	// scryptP 并行化参数
	scryptP = 1
	// scryptKeyLen 派生密钥长度（字节），与 HMAC-SHA256 key 等长
	scryptKeyLen = 32
)

// jwtAlg 本实现唯一支持的签名算法；校验时要求 header.alg 精确匹配（防算法混淆）
const jwtAlg = "HS256"

// jwtHeader 固定 alg/typ
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// jwtClaims 会话载荷。Host 绑定虚拟主机名，校验时与当前 host 比对（防 token 跨 host 复用）
type jwtClaims struct {
	Host string `json:"host"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

// deriveKey 由该 host 密码派生 JWT 签名密钥（M3 KDF v2，内部PRD §5/决策 D4/D7）：
// scrypt(password, salt=AuthKeyDerivationPrefixV2 字节, N=32768, r=8, p=1, keyLen=32)。
// 确定性输出（salt 为固定前缀字节）：同密码跨进程/跨重启派生结果一致，重启后已发
// token 仍然有效；v1（SHA-256）派生密钥升级后一次性失效（D4，用户重输密码）。
// 发放与校验一律走本函数，不存在版本协商路径。
func deriveKey(password string) []byte {
	key, err := scrypt.Key([]byte(password), []byte(AuthKeyDerivationPrefixV2), scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		// 固定合法参数（N 为 2 的幂、r*p < 2^30）下 scrypt 不可达错误；panic 兜底
		// 以防静默派生出弱 key
		panic(fmt.Sprintf("auth: scrypt derive key: %v", err))
	}
	return key
}

// IssueToken 签发绑定 host 的 HS256 JWT，有效期 = now + ttl
func IssueToken(key []byte, hostName string, now time.Time, ttl time.Duration) string {
	header := base64.RawURLEncoding.EncodeToString(mustJSON(jwtHeader{Alg: jwtAlg, Typ: "JWT"}))
	payload := base64.RawURLEncoding.EncodeToString(mustJSON(jwtClaims{
		Host: hostName,
		Iat:  now.Unix(),
		Exp:  now.Add(ttl).Unix(),
	}))
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyToken 校验 JWT：签名 → alg → host 绑定 → 过期，任一环节失败返回 false
// （调用方统一按未认证处理，不区分失败原因，不向请求方泄露细节）
func VerifyToken(token string, key []byte, hostName string, now time.Time) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	// 签名校验先于 payload 解析（签名不匹配的 token 不必解读其内容）
	rawSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	if !hmac.Equal(rawSig, mac.Sum(nil)) {
		return false
	}

	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var h jwtHeader
	if err := json.Unmarshal(rawHeader, &h); err != nil || h.Alg != jwtAlg {
		return false
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims jwtClaims
	if err := json.Unmarshal(rawPayload, &claims); err != nil {
		return false
	}
	if claims.Host != hostName {
		return false
	}
	if now.Unix() >= claims.Exp {
		return false
	}
	return true
}

func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// 固定结构体序列化不可达；panic 兜底以防静默签发坏 token
		panic(fmt.Sprintf("auth: marshal jwt part: %v", err))
	}
	return b
}
