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

const (
	ActionChangePublicKeys = "change-public-keys"
	ActionAssociate        = "associate"
	ActionGetLogins        = "get-logins"
	ActionTestAssociate    = "test-associate"
	ActionGetTOTP          = "get-totp"
)

type Request struct {
	Action        string      `json:"action"`
	ClientID      Base64Bytes `json:"clientID"`
	Nonce         Base64Bytes `json:"nonce"`
	Message       Base64Bytes `json:"message,omitempty"`
	TriggerUnlock bool        `json:"triggerUnlock,string,omitempty"`
}

type Response struct {
	Message Base64Bytes `json:"message"`
	Nonce   Base64Bytes `json:"nonce"`
	Error   *string     `json:"error"`
	Code    *int        `json:"errorCode,string"`
	Success *bool       `json:"success,string"`
	Version *string     `json:"version"`
	Hash    *string     `json:"hash"`
	ID      string      `json:"id"`
}

type ChangePublicKeysRequest struct {
	Request
	PulicKey Base64Bytes `json:"publicKey"`
}

type ChangePublicKeysResponse struct {
	Response
	PulicKey Base64Bytes `json:"publicKey"`
}

type TestAssociateRequest struct {
	Action string `json:"action"`
	DBKey
}

type TestAssociateResponse struct {
	Response
}

type AssociateRequest struct {
	Action string      `json:"action"`
	Key    Base64Bytes `json:"key"`   // client pubkey
	IDKey  Base64Bytes `json:"idKey"` // new id pubkey
}

type AssociateResponse struct {
	Response
}

type GetLoginsRequest struct {
	Action    string  `json:"action"`
	URL       string  `json:"url"`
	SubmitURL string  `json:"submitUrl,omitempty"`
	HTTPAuth  string  `json:"httpAuth,omitempty"`
	Keys      []DBKey `json:"keys,omitempty"`
}

type DBKey struct {
	ID  string      `json:"id"`  // saved DB identifier
	Key Base64Bytes `json:"key"` // saved pubkey
}

type GetLoginsResponse struct {
	Response
	Count   int          `json:"count"`
	Entries []LoginEntry `json:"entries"`
}

type LoginEntry struct {
	Login        string              `json:"login"`
	Name         string              `json:"name"`
	Password     string              `json:"password"`
	UUID         string              `json:"uuid"`
	StringFields []map[string]string `json:"stringFields"`
}

type GetTOTPRequest struct {
	Action string `json:"action"`
	UUID   string `json:"uuid"`
}

type GetTOTPResponse struct {
	Response
	TOTP string `json:"totp"`
}
