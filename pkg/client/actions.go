package client

import (
	"errors"
)

var ErrCantDecrypt = errors.New("can't decrypt message")
var ErrNoLoginsFound = errors.New("no logins found")

const (
	CodeCantDecrypt   = 4
	CodeNoLoginsFound = 15
)

func protocolError(msg string, code int) error {
	switch code {
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
			Action:   ChangePublicKeysAction,
			Nonce:    c.nonce()[:],
			ClientID: c.clientID[:],
		},
		PulicKey: c.pubkey[:],
	}

	if err = c.makeRequest(req, &resp); err != nil {
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
		Action: AssociateAction,
		Key:    c.pubkey[:],
		IDKey:  c.idKey[:],
	}

	if err = c.makeRequestWithMessage(m.Action, m, &resp); err != nil {
		return
	}

	c.identifier = resp.ID

	return
}

func (c *Client) TestAssociate() (resp TestAssociateResponseMessage, err error) {
	m := TestAssociateMessage{
		Action: TestAssociateAction,
		DBKey: DBKey{
			ID:  c.identifier,
			Key: c.idKey[:],
		},
	}

	if err = c.makeRequestWithMessage(m.Action, m, &resp); err != nil {
		return
	}

	c.identifier = resp.ID

	return
}

func (c *Client) GetLogins(url string) (resp GetLoginsResponseMessage, err error) {
	m := GetLoginsMessage{
		Action: GetLoginsAction,
		URL:    url,
		Keys: []DBKey{{
			ID:  c.identifier,
			Key: c.idKey[:],
		}},
	}

	if err = c.makeRequestWithMessage(m.Action, m, &resp); err != nil {
		return
	}

	return
}
