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
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net"

	"golang.org/x/crypto/nacl/box"
)

var ErrFailedToOpen = errors.New("failed to open message")

type Client struct {
	log *log.Logger

	// Session stuff
	conn         net.Conn
	privkey      [32]byte
	pubkey       [32]byte
	serverPubkey [32]byte
	clientID     [24]byte
	lastNonce    *[24]byte

	// Association (should be saved/loaded)
	idKey      [24]byte // client identifier key
	identifier string   // user-set identifier
}

func New(conn net.Conn, idKey *[24]byte, identifier string) (c *Client, err error) {
	pubkey, privkey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return
	}

	// nonce has the same size as clientID, so we can use it to get a random ID
	clientID, err := Nonce()
	if err != nil {
		return
	}

	nonce, err := Nonce()
	if err != nil {
		return
	}

	// TODO: add an option to set logger
	logWriter := ioutil.Discard

	c = &Client{
		log:       log.New(logWriter, "", log.Lmicroseconds),
		conn:      conn,
		privkey:   *privkey,
		pubkey:    *pubkey,
		clientID:  *clientID,
		lastNonce: nonce,

		idKey:      *idKey,
		identifier: identifier,
	}

	return c, nil
}

func (c *Client) nonce() *[24]byte {
	c.lastNonce = incrementNonce(c.lastNonce)

	return c.lastNonce
}

func (c *Client) AssociationData() (idKey [24]byte, identifier string) {
	return c.idKey, c.identifier
}

func (c *Client) send(request, response interface{}) (err error) {
	if err = json.NewEncoder(c.conn).Encode(request); err != nil {
		return
	}

	return json.NewDecoder(c.conn).Decode(response)
}

func (c *Client) sendMessageWithRetry(action string, message, response interface{}, triggerUnlock bool) (err error) {
	for {
		err = c.sendMessage(action, message, response, triggerUnlock)

		// TODO: find out why we can't open the response sometimes.
		// We obviously exchanged pubkeys and verified association successfully already.
		// A retry usually fixes this.
		if errors.Is(err, ErrFailedToOpen) {
			continue
		}

		return
	}
}

func (c *Client) sendMessage(action string, message, response interface{}, triggerUnlock bool) (err error) {
	msg, err := json.Marshal(message)
	if err != nil {
		return
	}

	c.log.Printf("-->MSG:\n%s\n", msg)

	nonce := c.nonce()

	req := Request{
		ClientID:      c.clientID[:],
		Action:        action,
		TriggerUnlock: triggerUnlock,
		Nonce:         Base64Bytes(nonce[:]),
		Message:       Base64Bytes(box.Seal([]byte{}, msg, nonce, &c.serverPubkey, &c.privkey)),
	}

	resp := &Response{}
	if err = c.send(req, resp); err != nil {
		return
	}

	if resp.Error != nil {
		return protocolError(*resp.Error, *resp.Code)
	}

	n := &[24]byte{}

	copy(n[:], resp.Nonce)

	c.lastNonce = n

	b, ok := box.Open([]byte{}, resp.Message, n, &c.serverPubkey, &c.privkey)
	if !ok {
		return ErrFailedToOpen
	}

	c.log.Printf("<--RECVMSG:\n%s\n", b)

	return json.Unmarshal(b, response)
}
