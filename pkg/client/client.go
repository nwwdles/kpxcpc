package client

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"net"

	"golang.org/x/crypto/nacl/box"
)

type Client struct {
	// Session
	conn         net.Conn
	privkey      [32]byte
	pubkey       [32]byte
	serverPubkey [32]byte
	clientID     [24]byte

	// Association
	idKey      [24]byte // client identifier key
	identifier string   // user-set identifier
}

func New(conn net.Conn, idKey *[24]byte, identifier string) (c *Client, err error) {
	pubkey, privkey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return
	}

	clientID, err := Nonce() // nonce has the same size as we want
	if err != nil {
		return
	}

	c = &Client{
		conn:     conn,
		privkey:  *privkey,
		pubkey:   *pubkey,
		clientID: *clientID,

		idKey:      *idKey,
		identifier: identifier,
	}

	return c, nil
}

func (c *Client) GetAssociation() (idKey [24]byte, identifier string) {
	return c.idKey, c.identifier
}

func (c *Client) makeRequestWithMessage(action string, message, response interface{}) (err error) {
	nonce, err := Nonce()
	if err != nil {
		return
	}

	msg, err := json.Marshal(message)
	if err != nil {
		return
	}

	log.Printf("-->MSG:\n%s\n", msg)

	req := Request{
		ClientID: c.clientID[:],
		Action:   action,
		Nonce:    Base64Bytes(nonce[:]),
		Message:  Base64Bytes(box.Seal([]byte{}, msg, nonce, &c.serverPubkey, &c.privkey)),
	}

	resp := &Response{}
	if err = makeRequest(c.conn, req, resp); err != nil {
		return
	}

	if resp.Error != nil {
		return errors.New(*resp.Error)
	}

	n := &[24]byte{}

	copy(n[:], resp.Nonce)

	b, ok := box.Open([]byte{}, resp.Message, n, &c.serverPubkey, &c.privkey)
	if !ok {
		return errors.New("failed to open message")
	}

	log.Println(string(b))

	return json.Unmarshal(b, response)
}
