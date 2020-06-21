package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/cupnoodles14/kpxch-go/pkg/client"
)

type Association struct {
	IDKey client.Base64Bytes `json:"idKey"`
	ID    string             `json:"id"`
}

func saveAssociation(fname string, c *client.Client) (err error) {
	idkey, ident := c.GetAssociation()
	a := &Association{
		IDKey: idkey[:],
		ID:    ident,
	}

	b, err := json.Marshal(a)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fname, b, 0600)
	if err != nil {
		return
	}

	return
}

func initClient(socketpath, fname string) (c *client.Client, err error) {
	conn, err := net.Dial("unix", socketpath)
	if err != nil {
		return
	}

	idKey, err := client.Nonce()
	if err != nil {
		return
	}

	a := &Association{IDKey: idKey[:]}

	b, err := ioutil.ReadFile(fname)
	if err == nil {
		err = json.Unmarshal(b, a)
		if err != nil {
			return // corrupted file?
		}
	}

	k := &[24]byte{}
	copy(k[:], a.IDKey)

	c, err = client.New(conn, k, a.ID)

	return
}

func connect(socketpath, fname string) (c *client.Client, err error) {
	c, err = initClient(socketpath, fname)
	if err != nil {
		return
	}

	_, err = c.ChangePublicKeys()
	if err != nil {
		return
	}

	_, err = c.TestAssociate()
	if err != nil {
		if _, err = c.Associate(); err != nil {
			return
		}

		if err = saveAssociation(fname, c); err != nil {
			return
		}
	}

	return c, err
}

func main() {
	const associationFile = "assoc.json"

	c, err := connect(os.Getenv("XDG_RUNTIME_DIR")+"/kpxc_server", associationFile)
	if err != nil {
		panic(err)
	}

	logins, err := c.GetLogins("kpxch://sudo-soba")
	if err != nil {
		panic(err)
	}

	b, err := json.Marshal(logins.Entries)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(b))
}
