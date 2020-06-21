package client

import (
	"errors"
)

func (c *Client) ChangePublicKeys() (resp ChangePublicKeysResponse, err error) {
	nonce, err := Nonce()
	if err != nil {
		return
	}

	req := ChangePublicKeysRequest{
		Request: Request{
			Action:   ChangePublicKeysAction,
			Nonce:    nonce[:],
			ClientID: c.clientID[:],
		},
		PulicKey: c.pubkey[:],
	}

	if err = makeRequest(c.conn, req, &resp); err != nil {
		return
	}

	if resp.Error != nil {
		err = errors.New(*resp.Error)
		return
	}

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
