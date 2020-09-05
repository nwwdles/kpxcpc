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
package client

import (
	"errors"
)

var (
	ErrDBNotOpen     = errors.New("database not open")
	ErrCantDecrypt   = errors.New("can't decrypt message")
	ErrNoLoginsFound = errors.New("no logins found")
)

const (
	CodeDBNotOpen     = 1
	CodeCantDecrypt   = 4
	CodeNoLoginsFound = 15
)

func protocolError(msg string, code int) error {
	switch code {
	case CodeDBNotOpen:
		return ErrDBNotOpen
	case CodeCantDecrypt:
		return ErrCantDecrypt
	case CodeNoLoginsFound:
		return ErrNoLoginsFound
	default:
		return errors.New(msg) // nolint
	}
}

func (c *Client) ChangePublicKeys() (resp ChangePublicKeysResponse, err error) {
	req := ChangePublicKeysRequest{
		Request: Request{
			Action:   ActionChangePublicKeys,
			Nonce:    c.nonce()[:],
			ClientID: c.clientID[:],
		},
		PulicKey: c.pubkey[:],
	}

	if err = c.Send(req, &resp); err != nil {
		return
	}

	if resp.Error != nil {
		err = protocolError(*resp.Error, *resp.Code)
		return
	}

	copy(c.lastNonce[:], resp.Nonce)
	copy(c.serverPubkey[:], resp.PulicKey)

	return resp, err
}

func (c *Client) Associate() (resp AssociateResponseMessage, err error) {
	m := AssociateMessage{
		Action: ActionAssociate,
		Key:    c.pubkey[:],
		IDKey:  c.idKey[:],
	}

	if err = c.SendMessageWithRetry(m.Action, m, &resp, true); err != nil {
		return
	}

	c.identifier = resp.ID

	return
}

func (c *Client) TestAssociate(triggerUnlock bool) (resp TestAssociateResponseMessage, err error) {
	m := TestAssociateMessage{
		Action: ActionTestAssociate,
		DBKey: DBKey{
			ID:  c.identifier,
			Key: c.idKey[:],
		},
	}

	if err = c.SendMessageWithRetry(m.Action, m, &resp, triggerUnlock); err != nil {
		return
	}

	return
}

func (c *Client) GetLogins(url string) (resp GetLoginsResponseMessage, err error) {
	m := GetLoginsMessage{
		Action: ActionGetLogins,
		URL:    url,
		Keys: []DBKey{{
			ID:  c.identifier,
			Key: c.idKey[:],
		}},
	}

	if err = c.SendMessageWithRetry(m.Action, m, &resp, true); err != nil {
		return
	}

	return
}
