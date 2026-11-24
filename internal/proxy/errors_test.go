package proxy

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
)

func TestDetectUpstreamErrorType(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantType UpstreamErrorType
	}{
		{
			name:     "nil error",
			err:      nil,
			wantType: UpstreamErrorUnknown,
		},
		{
			name:     "timeout error",
			err:      &net.OpError{Op: "dial", Err: &timeoutErr{}},
			wantType: UpstreamErrorTimeout,
		},
		{
			name:     "certificate alone should not be SSL",
			err:      errors.New("certificate verification needed"),
			wantType: UpstreamErrorUnknown,
		},
		{
			name:     "SSL alone should not be SSL",
			err:      errors.New("SSL is required"),
			wantType: UpstreamErrorUnknown,
		},
		{
			name:     "TLS alone should not be SSL",
			err:      errors.New("TLS is recommended"),
			wantType: UpstreamErrorUnknown,
		},
		{
			name:     "x509 prefix should be SSL",
			err:      errors.New("x509: certificate signed by unknown authority"),
			wantType: UpstreamErrorSSL,
		},
		{
			name:     "tls: prefix should be SSL",
			err:      errors.New("tls: handshake failure"),
			wantType: UpstreamErrorSSL,
		},
		{
			name:     "timeout with TLS in message should be timeout",
			err:      &net.OpError{Op: "dial", Err: &timeoutErr{msg: "TLS connection timed out"}},
			wantType: UpstreamErrorTimeout,
		},
		{
			name:     "certificate verification error type",
			err:      &tls.CertificateVerificationError{},
			wantType: UpstreamErrorSSL,
		},
		{
			name:     "DNS failure",
			err:      &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "example.com"}},
			wantType: UpstreamErrorDNSFailure,
		},
	}

	for _, tt := range tests {
		gotType, _ := detectUpstreamErrorType(tt.err)
		if gotType != tt.wantType {
			t.Errorf("%s: detectUpstreamErrorType() gotType = %v, want %v", tt.name, gotType, tt.wantType)
		}
	}
}

type timeoutErr struct {
	msg string
}

func (e *timeoutErr) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "i/o timeout"
}

func (e *timeoutErr) Timeout() bool   { return true }
func (e *timeoutErr) Temporary() bool { return false }

func TestGetHTTPStatusCodeForError(t *testing.T) {
	tests := []struct {
		errType UpstreamErrorType
		want    int
	}{
		{UpstreamErrorTimeout, 504},
		{UpstreamErrorConnectionRefused, 502},
		{UpstreamErrorDNSFailure, 502},
		{UpstreamErrorSSL, 502},
		{UpstreamErrorNoRoute, 502},
		{UpstreamErrorUnknown, 502},
	}

	for _, tt := range tests {
		got := getHTTPStatusCodeForError(tt.errType)
		if got != tt.want {
			t.Errorf("getHTTPStatusCodeForError(%v) = %d, want %d", tt.errType, got, tt.want)
		}
	}
}
