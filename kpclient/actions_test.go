// The MIT License (MIT)
//
// Copyright (c) 2020 cupnoodles
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
//
package kpclient

import (
	"crypto/rand"
	"encoding/json"
	"net"
	"testing"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/nettest"
)

type mockKeePass struct {
	l       net.Listener
	handler func(net.Conn)
	done    chan struct{}
}

func newMockKeePass(handler func(c net.Conn)) *mockKeePass {
	l, err := nettest.NewLocalListener("unix")
	if err != nil {
		panic(err)
	}
	m := &mockKeePass{
		l:       l,
		done:    make(chan struct{}),
		handler: handler,
	}
	go m.listenAndServe()
	return m
}

func (m *mockKeePass) Close() {
	err := m.l.Close()
	if err != nil {
		panic(err)
	}
	<-m.done
}

func (m *mockKeePass) listenAndServe() {
	defer close(m.done)
	for {
		c, err := m.l.Accept()
		if err != nil {
			return
		}
		go m.handler(c)
	}
}

func (m *mockKeePass) Conn() net.Conn {
	c, err := net.Dial("unix", m.l.Addr().String())
	if err != nil {
		panic(err)
	}
	return c
}

func Test_newMockKeePass(t *testing.T) {
	m := newMockKeePass(func(c net.Conn) {})
	m.Conn()
	m.Close()
}

func TestClient_ChangePublicKeys(t *testing.T) {
	tests := []struct {
		name     string
		resp     interface{}
		wantResp ChangePublicKeysResponse
		wantErr  bool
	}{
		{
			resp: ChangePublicKeysResponse{},
		},
		{
			resp:    "a",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := newMockKeePass(func(c net.Conn) {
				var req ChangePublicKeysRequest
				err := json.NewDecoder(c).Decode(&req)
				if err != nil {
					t.Error(err)
				}
				if req.Action != ActionChangePublicKeys ||
					len(req.Nonce) == 0 ||
					len(req.PulicKey) == 0 {
					t.Errorf("bad request: %+v", req)
				}
				err = json.NewEncoder(c).Encode(tt.resp)
				if err != nil {
					t.Error(err)
				}
				c.Close()
			})
			defer k.Close()

			c, err := New(k.Conn(), nil, nil, "")
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.ChangePublicKeys()
			if (err != nil) != tt.wantErr {
				t.Fatalf("resp=%v wantErr=%v err=%v", resp, tt.wantErr, err)
			}
		})
	}
}

func TestClient_Associate(t *testing.T) {
	spubkey, sprivkey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		resp     interface{}
		wantResp AssociateRequest
		wantErr  bool
	}{
		{
			resp: AssociateResponse{
				Response: Response{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pubkey [32]byte
			k := newMockKeePass(func(c net.Conn) {
				var req Request
				err := json.NewDecoder(c).Decode(&req)
				if err != nil {
					t.Error(err)
				}
				if req.Action != ActionAssociate ||
					len(req.Nonce) == 0 {
					t.Errorf("bad request: %+v", req)
				}
				nonce := incrementNonce((*[24]byte)(req.Nonce))[:]
				resp := AssociateResponse{Response: Response{
					Nonce:   nonce,
					Message: box.Seal([]byte{}, []byte(`{}`), (*[24]byte)(nonce), &pubkey, sprivkey),
				}}
				err = json.NewEncoder(c).Encode(resp)
				if err != nil {
					t.Error(err)
				}
				c.Close()
			})
			defer k.Close()

			c, err := New(k.Conn(), nil, nil, "")
			if err != nil {
				t.Fatal(err)
			}
			c.serverPubkey = *spubkey

			pubkey = c.pubkey

			resp, err := c.Associate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("resp=%v wantErr=%v err=%v", resp, tt.wantErr, err)
			}
		})
	}
}
