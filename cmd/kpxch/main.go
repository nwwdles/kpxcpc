package main

import "github.com/cupnoodles14/kpxch-go/pkg/client"

func main() {
	c := client.New()

	err := c.ChangePublicKeys()
	if err != nil {
		panic(err)
	}

	err = c.Associate()
	if err != nil {
		panic(err)
	}

	c.GetLogins("kpxch://sudo-soba")
}
