package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cupnoodles14/kpxcpc/pkg/client"
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

	err = os.Mkdir(filepath.Dir(fname), 0700)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return
		}
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
	if c, err = initClient(socketpath, fname); err != nil {
		return
	}

	triggerUnlock := true
	waitForUnlock := true

	for {
		if _, err = c.ChangePublicKeys(); err != nil {
			return
		}

		if _, err = c.TestAssociate(triggerUnlock); err != nil {
			// TODO: find out why this is happening
			if errors.Is(err, client.ErrCantDecrypt) {
				continue
			}

			if waitForUnlock && errors.Is(err, client.ErrDBNotOpen) { // todo: retries
				time.Sleep(time.Second)

				triggerUnlock = false

				fmt.Fprintf(os.Stderr, "Waiting for DB to be unlocked...\r")

				continue
			}

			if _, err = c.Associate(); err != nil {
				return
			}

			if err = saveAssociation(fname, c); err != nil {
				return
			}
		}

		break
	}

	return c, err
}

func entriesJSONPrint(entries []client.LoginEntry) {
	b, err := json.Marshal(entries)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(b))
}

func entriesPrintf(format, fieldsformat string, entries []client.LoginEntry) {
	for i := range entries {
		e := &entries[i]
		r := strings.NewReplacer(
			"%n", e.Name,
			"%p", e.Password,
			"%l", e.Login,
			"%u", e.UUID,
		)
		fmt.Print(r.Replace(format))

		for _, v := range e.StringFields {
			for k, v := range v {
				r := strings.NewReplacer("%k", k, "%v", v)
				fmt.Print(r.Replace(fieldsformat))
			}
		}
	}
}

func main() {
	datahome := os.Getenv("XDG_DATA_HOME")
	if datahome == "" {
		datahome = os.Getenv("HOME") + "/.local/share"
	}

	identity := flag.String("identity", datahome+"/kpxcpc/identity.json",
		"set identity file")
	printJSON := flag.Bool("json", false,
		"print json")
	socket := flag.String("socket", os.Getenv("XDG_RUNTIME_DIR")+"/kpxc_server",
		"path to keepassxc-proxy socket")
	fieldsformat := flag.String("ffmt", ``,
		"format string for stringFields\n  key - %k, value - %v")
	format := flag.String("fmt", `%p`,
		"format string for main entry fields\n  name - %n, login - %l, pass - %p, uuid - %u\n")

	flag.Parse()

	urls := flag.Args()

	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "Please provide at least one URL argument.")

		return
	}

	c, err := connect(*socket, *identity)
	if err != nil {
		panic(err)
	}

	var logins client.GetLoginsResponseMessage

	logins, err = c.GetLogins(urls[0])
	if err != nil {
		if errors.Is(err, client.ErrNoLoginsFound) {
			fmt.Fprintln(os.Stderr, "No logins found.")
			os.Exit(1)
		}

		panic(err)
	}

	if *printJSON {
		entriesJSONPrint(logins.Entries)
		return
	}

	*format, err = strconv.Unquote(`"` + *format + `"`)
	if err != nil {
		panic(err)
	}

	*fieldsformat, err = strconv.Unquote(`"` + *fieldsformat + `"`)
	if err != nil {
		panic(err)
	}

	entriesPrintf(*format, *fieldsformat, logins.Entries)
}
