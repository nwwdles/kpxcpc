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
	"errors"
)

var (
	ErrUnknownError               = errors.New("unknown error")
	ErrDatabaseNotOpened          = errors.New("database not opened")
	ErrDatabaseHashNotReceived    = errors.New("database hash not received")
	ErrClientPublicKeyNotReceived = errors.New("client public key not received")
	ErrCannotDecryptMessage       = errors.New("cannot decrypt message")
	ErrTimeoutOrNotConnected      = errors.New("timeout or not connected")
	ErrActionCancelledOrDenied    = errors.New("action cancelled or denied")
	ErrPublicKeyNotFound          = errors.New("public key not found")
	ErrAssociationFailed          = errors.New("association failed")
	ErrKeyChangeFailed            = errors.New("key change failed")
	ErrEncryptionKeyUnrecognized  = errors.New("encryption key unrecognized")
	ErrNoSavedDatabasesFound      = errors.New("no saved databases found")
	ErrIncorrectAction            = errors.New("incorrect action")
	ErrEmptyMessageReceived       = errors.New("empty message received")
	ErrNoURLProvided              = errors.New("no url provided")
	ErrNoLoginsFound              = errors.New("no logins found")
)

const (
	CodeUnknownError               = 0
	CodeDatabaseNotOpened          = 1
	CodeDatabaseHashNotReceived    = 2
	CodeClientPublicKeyNotReceived = 3
	CodeCannotDecryptMessage       = 4
	CodeTimeoutOrNotConnected      = 5
	CodeActionCancelledOrDenied    = 6
	CodePublicKeyNotFound          = 7
	CodeAssociationFailed          = 8
	CodeKeyChangeFailed            = 9
	CodeEncryptionKeyUnrecognized  = 10
	CodeNoSavedDatabasesFound      = 11
	CodeIncorrectAction            = 12
	CodeEmptyMessageReceived       = 13
	CodeNoURLProvided              = 14
	CodeNoLoginsFound              = 15
)

func protocolError(msg string, code int) error {
	switch code {
	case CodeUnknownError:
		return ErrUnknownError
	case CodeDatabaseNotOpened:
		return ErrDatabaseNotOpened
	case CodeDatabaseHashNotReceived:
		return ErrDatabaseHashNotReceived
	case CodeClientPublicKeyNotReceived:
		return ErrClientPublicKeyNotReceived
	case CodeCannotDecryptMessage:
		return ErrCannotDecryptMessage
	case CodeTimeoutOrNotConnected:
		return ErrTimeoutOrNotConnected
	case CodeActionCancelledOrDenied:
		return ErrActionCancelledOrDenied
	case CodePublicKeyNotFound:
		return ErrPublicKeyNotFound
	case CodeAssociationFailed:
		return ErrAssociationFailed
	case CodeKeyChangeFailed:
		return ErrKeyChangeFailed
	case CodeEncryptionKeyUnrecognized:
		return ErrEncryptionKeyUnrecognized
	case CodeNoSavedDatabasesFound:
		return ErrNoSavedDatabasesFound
	case CodeIncorrectAction:
		return ErrIncorrectAction
	case CodeEmptyMessageReceived:
		return ErrEmptyMessageReceived
	case CodeNoURLProvided:
		return ErrNoURLProvided
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

	if err = c.send(req, &resp); err != nil {
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

func (c *Client) Associate() (resp AssociateResponse, err error) {
	m := AssociateRequest{
		Action: ActionAssociate,
		Key:    c.pubkey[:],
		IDKey:  c.idKey[:],
	}

	if err = c.sendMessageWithRetry(m.Action, m, &resp, true); err != nil {
		return
	}

	c.identifier = resp.ID

	return
}

func (c *Client) TestAssociate(triggerUnlock bool) (resp TestAssociateResponse, err error) {
	m := TestAssociateRequest{
		Action: ActionTestAssociate,
		DBKey: DBKey{
			ID:  c.identifier,
			Key: c.idKey[:],
		},
	}

	err = c.sendMessageWithRetry(m.Action, m, &resp, triggerUnlock)

	return
}

func (c *Client) GetLogins(url string) (resp GetLoginsResponse, err error) {
	m := GetLoginsRequest{
		Action: ActionGetLogins,
		URL:    url,
		Keys: []DBKey{{
			ID:  c.identifier,
			Key: c.idKey[:],
		}},
	}

	err = c.sendMessageWithRetry(m.Action, m, &resp, true)

	return
}

func (c *Client) GetTOTP(uuid string) (resp GetTOTPResponse, err error) {
	m := GetTOTPRequest{
		Action: ActionGetTOTP,
		UUID:   uuid,
	}

	err = c.sendMessageWithRetry(m.Action, m, &resp, true)

	return
}
