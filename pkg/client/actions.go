package client

import (
	"errors"

	"github.com/cupnoodles14/kpxch-go/pkg/protocol"
)

func (c *Client) ChangePublicKeys() (err error) {
	nonce, err := Nonce()
	if err != nil {
		return
	}

	req := protocol.ChangePublicKeysRequest{
		Request: protocol.Request{
			Action:   protocol.ChangePublicKeysAction,
			Nonce:    encode(nonce[:]),
			ClientID: "golang",
		},
		PulicKey: encode(c.pubkey[:]),
	}

	resp := protocol.ChangePublicKeysResponse{}
	if err = MakeRequest(c.conn, req, &resp); err != nil {
		return
	}

	if resp.Error != nil {
		return errors.New(*resp.Error)
	}

	c.serverPubkey = &[32]byte{}

	key, err := decode(resp.PulicKey)
	if err != nil {
		return
	}

	copy(c.serverPubkey[:], key)

	return err
}

func (c *Client) Associate() (err error) {
	m := protocol.AssociateMessage{
		Action: protocol.AssociateAction,
		Key:    encode(c.pubkey[:]),
		IDKey:  encode(c.idKey[:]),
	}

	resp := protocol.AssociateResponseMessage{}
	if err = c.encryptedRequest(m.Action, m, &resp); err != nil {
		return
	}

	c.identifier = resp.ID

	return err
}

func (c *Client) GetLogins(url string) (err error) {
	m := protocol.GetLoginsMessage{
		Action: protocol.GetLoginsAction,
		URL:    url,
		Keys: []protocol.Key{{
			ID:  c.identifier,
			Key: encode(c.idKey[:]),
		}},
	}

	resp := protocol.AssociateResponseMessage{}
	if err = c.encryptedRequest(m.Action, m, &resp); err != nil {
		return
	}

	c.identifier = resp.ID

	return err
}
