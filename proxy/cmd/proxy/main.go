package main

import (
	"time"

	"github.com/idigitalflame/switchproxy/proxy"
)

func main() {

	p := proxy.NewProxy("0.0.0.0:8080")

	s, _ := proxy.NewSwitch("http://ifconfig.co", time.Duration(5)*time.Second)
	s2, _ := proxy.NewSwitch("http://goolme.com", time.Duration(5)*time.Second)

	p.Primary(s)
	p.AddSecondary(s2)

	p.Start()
}
