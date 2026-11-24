package proxy

import (
	"bufio"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// generateWebSocketAcceptKey generates the Sec-WebSocket-Accept header value
func generateWebSocketAcceptKey(key string) string {
	const magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magicString))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// isControlFrame checks if the WebSocket frame is a control frame (ping/pong/close)
func isControlFrame(opcode byte) bool {
	return opcode >= 0x08 && opcode <= 0x0F
}

// negotiateExtensions negotiates WebSocket extensions between client and backend
// 返回客户端和后端都支持的扩展，保留原始参数
func negotiateExtensions(clientExts, backendExts string) string {
	if clientExts == "" || backendExts == "" {
		return ""
	}

	clientExtList := parseWebSocketExtensions(clientExts)
	backendExtList := parseWebSocketExtensions(backendExts)

	var accepted []string
	for _, clientExt := range clientExtList {
		for _, backendExt := range backendExtList {
			if strings.EqualFold(clientExt.Name, backendExt.Name) {
				// P2-13: 使用后端返回的参数（后端协商后的参数），而非丢弃
				// 后端的响应包含协商后的最终参数集
				accepted = append(accepted, backendExt.Raw)
				break
			}
		}
	}

	return strings.Join(accepted, ", ")
}

// wsExtension 表示解析后的 WebSocket 扩展
type wsExtension struct {
	Name string // 扩展名，如 "permessage-deflate"
	Raw  string // 原始字符串（含参数），如 "permessage-deflate; client_max_window_bits"
}

// parseWebSocketExtensions parses the Sec-WebSocket-Extensions header value
// 返回扩展名和原始字符串，以便后续协商时保留参数
func parseWebSocketExtensions(header string) []wsExtension {
	exts := strings.Split(header, ",")
	result := make([]wsExtension, 0, len(exts))
	for _, ext := range exts {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		name := ext
		if idx := strings.Index(ext, ";"); idx != -1 {
			name = strings.TrimSpace(ext[:idx])
		}
		result = append(result, wsExtension{
			Name: name,
			Raw:  ext,
		})
	}
	return result
}

// WebSocket opcodes
const (
	wsOpcodeContinuation = 0x00
	wsOpcodeText         = 0x01
	wsOpcodeBinary       = 0x02
	wsOpcodeClose        = 0x08
	wsOpcodePing         = 0x09
	wsOpcodePong         = 0x0A
)

// WebSocket timeout defaults — 可通过 ServerConfig.WebSocket 覆盖
const (
	wsHandshakeTimeout    = 30 * time.Second
	wsReadTimeout         = 60 * time.Second
	wsIdleTimeout         = 5 * time.Minute
	wsPingInterval        = 30 * time.Second
	wsMaxControlFrameSize = 125     // RFC 6455: control frames must have payload <= 125 bytes
	wsMaxFramePayloadSize = 1 << 20 // 1MB, 防止恶意超大帧导致 OOM
)

// readWebSocketFrame reads a single WebSocket frame from the connection
// source 表示帧来源方向："client" 或 "backend"，用于校验掩码要求
// permessageDeflate 表示是否协商了 permessage-deflate 扩展，协商后允许 RSV1 位
func readWebSocketFrame(reader *bufio.Reader, source string, permessageDeflate bool) ([]byte, error) {
	// Read first byte (FIN, RSV, opcode)
	b1, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	// C12: 校验 RSV 位（b1 的 bits 4-6）
	// RSV1 (0x40) 在协商 permessage-deflate 后允许设置（表示压缩帧）
	// RSV2 (0x20) 和 RSV3 (0x10) 始终必须为 0
	if permessageDeflate {
		// 仅允许 RSV1，RSV2 和 RSV3 必须为 0
		if b1&0x30 != 0 {
			return nil, fmt.Errorf("invalid WebSocket frame: RSV2/RSV3 bits must be 0, got 0x%02x", b1)
		}
	} else {
		// 未协商扩展时所有 RSV 位必须为 0
		if b1&0x70 != 0 {
			return nil, fmt.Errorf("invalid WebSocket frame: RSV bits must be 0, got 0x%02x", b1)
		}
	}

	opcode := b1 & 0x0F

	// P2-10: 保留 opcode (0x03-0x07, 0x0B-0x0F) 未定义，按 RFC 6455 必须关闭连接
	if (opcode >= 0x03 && opcode <= 0x07) || (opcode >= 0x0B && opcode <= 0x0F) {
		return nil, fmt.Errorf("invalid WebSocket frame: reserved opcode 0x%02x", opcode)
	}

	// P2-11: 控制帧必须 FIN=1（不可分片）
	fin := (b1 & 0x80) != 0
	if isControlFrame(opcode) && !fin {
		return nil, fmt.Errorf("invalid WebSocket frame: control frame (opcode 0x%02x) must have FIN=1", opcode)
	}

	// Read second byte (MASK, payload length)
	b2, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	// P2-12: client→server 帧必须掩码，server→client 帧不得掩码
	masked := (b2 & 0x80) != 0
	if source == "client" && !masked {
		return nil, fmt.Errorf("invalid WebSocket frame: client-to-server frame must be masked")
	}
	if source == "backend" && masked {
		return nil, fmt.Errorf("invalid WebSocket frame: server-to-client frame must not be masked")
	}

	// Build header bytes
	header := []byte{b1, b2}

	payloadLen := int(b2 & 0x7F)
	if payloadLen == 126 {
		lenBytes := make([]byte, 2)
		if _, err := io.ReadFull(reader, lenBytes); err != nil {
			return nil, err
		}
		header = append(header, lenBytes...)
		payloadLen = int(lenBytes[0])<<8 | int(lenBytes[1])
	} else if payloadLen == 127 {
		lenBytes := make([]byte, 8)
		if _, err := io.ReadFull(reader, lenBytes); err != nil {
			return nil, err
		}
		header = append(header, lenBytes...)
		payloadLen64 := uint64(lenBytes[0])<<56 | uint64(lenBytes[1])<<48 |
			uint64(lenBytes[2])<<40 | uint64(lenBytes[3])<<32 |
			uint64(lenBytes[4])<<24 | uint64(lenBytes[5])<<16 |
			uint64(lenBytes[6])<<8 | uint64(lenBytes[7])
		// Compare as uint64 before int conversion to prevent overflow on 32-bit platforms
		if payloadLen64 > uint64(wsMaxFramePayloadSize) {
			return nil, fmt.Errorf("frame payload too large: %d bytes (max %d)", payloadLen64, wsMaxFramePayloadSize)
		}
		payloadLen = int(payloadLen64)
	}

	// Check control frame payload size
	if isControlFrame(opcode) && payloadLen > wsMaxControlFrameSize {
		return nil, fmt.Errorf("control frame payload too large: %d bytes (max %d)", payloadLen, wsMaxControlFrameSize)
	}

	// Check total frame payload size to prevent OOM from malicious oversized frames
	if payloadLen > wsMaxFramePayloadSize {
		return nil, fmt.Errorf("frame payload too large: %d bytes (max %d)", payloadLen, wsMaxFramePayloadSize)
	}

	// Read masking key if present
	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(reader, maskKey); err != nil {
			return nil, err
		}
		header = append(header, maskKey...)
	}

	// Read payload
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
	}

	// Reconstruct the frame - include header and payload as-is
	frame := append(header, payload...)
	return frame, nil
}

// writeWebSocketFrame writes a WebSocket frame to the connection
func writeWebSocketFrame(writer *bufio.Writer, frame []byte) error {
	_, err := writer.Write(frame)
	if err != nil {
		return err
	}
	return writer.Flush()
}

// wsConnWriter 线程安全的 WebSocket 连接写入器
// 确保多个 goroutine 并发写入同一 net.Conn 时不会产生帧交错损坏
type wsConnWriter struct {
	mu   sync.Mutex
	buf  *bufio.Writer
	conn net.Conn
}

func newWsConnWriter(conn net.Conn) *wsConnWriter {
	return &wsConnWriter{
		buf:  bufio.NewWriter(conn),
		conn: conn,
	}
}

// writeWriteTimeout 是写帧超时时间
const writeWriteTimeout = 10 * time.Second

func (w *wsConnWriter) writeFrame(frame []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	// P2-14: 设置写超时，TCP 缓冲区满时防止 goroutine 无限阻塞
	if w.conn != nil {
		w.conn.SetWriteDeadline(time.Now().Add(writeWriteTimeout))
	}
	if _, err := w.buf.Write(frame); err != nil {
		return err
	}
	return w.buf.Flush()
}

// createPongFrameToClient 创建发往客户端的 pong 帧（不掩码）
// RFC 6455 Section 5.3: server 不得掩码任何发往客户端的帧
func createPongFrameToClient(pingFrame []byte) ([]byte, error) {
	if len(pingFrame) < 2 {
		return nil, fmt.Errorf("ping frame too short: %d bytes (min 2)", len(pingFrame))
	}

	b2 := pingFrame[1]
	masked := (b2 & 0x80) != 0

	pongB1 := (pingFrame[0] & 0xF0) | wsOpcodePong
	pongB2 := b2 & 0x7F // 清除 MASK 位

	pongFrame := []byte{pongB1, pongB2}

	payloadLen := int(b2 & 0x7F)
	offset := 2
	if payloadLen == 126 {
		if len(pingFrame) < offset+2 {
			return nil, fmt.Errorf("ping frame too short for 126 payload length: need %d bytes, got %d", offset+2, len(pingFrame))
		}
		pongFrame = append(pongFrame, pingFrame[offset:offset+2]...)
		offset += 2
	} else if payloadLen == 127 {
		if len(pingFrame) < offset+8 {
			return nil, fmt.Errorf("ping frame too short for 127 payload length: need %d bytes, got %d", offset+8, len(pingFrame))
		}
		pongFrame = append(pongFrame, pingFrame[offset:offset+8]...)
		offset += 8
	}

	if masked {
		if len(pingFrame) < offset+4 {
			return nil, fmt.Errorf("ping frame too short for mask key: need %d bytes, got %d", offset+4, len(pingFrame))
		}
		maskKey := pingFrame[offset : offset+4]
		offset += 4
		if payloadLen > 0 {
			if len(pingFrame) < offset+payloadLen {
				return nil, fmt.Errorf("ping frame too short for masked payload: need %d bytes, got %d", offset+payloadLen, len(pingFrame))
			}
			payload := make([]byte, payloadLen)
			copy(payload, pingFrame[offset:offset+payloadLen])
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
			pongFrame = append(pongFrame, payload...)
		}
	} else {
		if payloadLen > 0 {
			if len(pingFrame) < offset+payloadLen {
				return nil, fmt.Errorf("ping frame too short for payload: need %d bytes, got %d", offset+payloadLen, len(pingFrame))
			}
			pongFrame = append(pongFrame, pingFrame[offset:offset+payloadLen]...)
		}
	}

	return pongFrame, nil
}

// createPongFrameToBackend 创建发往后端的 pong 帧（必须掩码）
// RFC 6455 Section 5.3: client 必须掩码所有发往 server 的帧
func createPongFrameToBackend(pingFrame []byte) ([]byte, error) {
	if len(pingFrame) < 2 {
		return nil, fmt.Errorf("ping frame too short: %d bytes (min 2)", len(pingFrame))
	}

	b2 := pingFrame[1]
	masked := (b2 & 0x80) != 0

	pongB1 := (pingFrame[0] & 0xF0) | wsOpcodePong
	pongB2 := b2 | 0x80 // 设置 MASK 位

	pongFrame := []byte{pongB1, pongB2}

	payloadLen := int(b2 & 0x7F)
	offset := 2
	if payloadLen == 126 {
		if len(pingFrame) < offset+2 {
			return nil, fmt.Errorf("ping frame too short for 126 payload length: need %d bytes, got %d", offset+2, len(pingFrame))
		}
		pongFrame = append(pongFrame, pingFrame[offset:offset+2]...)
		offset += 2
	} else if payloadLen == 127 {
		if len(pingFrame) < offset+8 {
			return nil, fmt.Errorf("ping frame too short for 127 payload length: need %d bytes, got %d", offset+8, len(pingFrame))
		}
		pongFrame = append(pongFrame, pingFrame[offset:offset+8]...)
		offset += 8
	}

	var payload []byte
	if masked {
		if len(pingFrame) < offset+4 {
			return nil, fmt.Errorf("ping frame too short for mask key: need %d bytes, got %d", offset+4, len(pingFrame))
		}
		maskKey := pingFrame[offset : offset+4]
		offset += 4
		if payloadLen > 0 {
			if len(pingFrame) < offset+payloadLen {
				return nil, fmt.Errorf("ping frame too short for masked payload: need %d bytes, got %d", offset+payloadLen, len(pingFrame))
			}
			payload = make([]byte, payloadLen)
			copy(payload, pingFrame[offset:offset+payloadLen])
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}
	} else {
		if payloadLen > 0 {
			if len(pingFrame) < offset+payloadLen {
				return nil, fmt.Errorf("ping frame too short for payload: need %d bytes, got %d", offset+payloadLen, len(pingFrame))
			}
			payload = make([]byte, payloadLen)
			copy(payload, pingFrame[offset:offset+payloadLen])
		}
	}

	var newMask [4]byte
	if _, err := crand.Read(newMask[:]); err != nil {
		return nil, fmt.Errorf("failed to generate pong mask key: %w", err)
	}
	pongFrame = append(pongFrame, newMask[:]...)
	if payloadLen > 0 {
		maskedPayload := make([]byte, payloadLen)
		for i := range payload {
			maskedPayload[i] = payload[i] ^ newMask[i%4]
		}
		pongFrame = append(pongFrame, maskedPayload...)
	}

	return pongFrame, nil
}

// createPingFrame creates a masked ping frame for keepalive
func createPingFrame() ([]byte, error) {
	frame := make([]byte, 6)
	frame[0] = wsOpcodePing | 0x80
	frame[1] = 0x80 // masked, payload length 0
	if _, err := crand.Read(frame[2:6]); err != nil {
		return nil, fmt.Errorf("failed to generate ping mask key: %w", err)
	}
	return frame, nil
}

// createPingFrameToClient creates an unmasked ping frame for keepalive to client
// RFC 6455 Section 5.3: server must not mask any frame sent to client
func createPingFrameToClient() ([]byte, error) {
	frame := make([]byte, 2)
	frame[0] = wsOpcodePing | 0x80
	frame[1] = 0x00 // not masked, payload length 0
	return frame, nil
}
