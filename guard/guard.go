package guard

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Guard struct {
	Port      string     `json:"port"`
	Passports []Passport `json:"passports"`
}

type Passport struct {
	Path string `json:"path"`
	Name string `json:"name"`
	IP   string `json:"ip"`
}

type Suspect struct {
	Time  time.Time `json:"time"`
	Count int       `json:"count"`
}

type Captain struct {
	HTTPort  string  `json:"httpPort"`
	Ports    []Guard `json:"ports"`
	Suspects map[string]*Suspect
}

func (p *Captain) guardSelf() error {
	for ip := range p.Suspects {
		if p.Suspects[ip].Count < 5 {
			continue
		}
		if err := runIptables(fmt.Sprintf("iptables -I INPUT --source %s -p tcp --dport %s -j REJECT", ip, p.HTTPort)); err != nil {
			return err
		}
		log.Printf("put ip %s in port %s blacklist", p.HTTPort, ip)
	}
	return nil
}

func (p *Guard) iptables() error {
	if err := runIptables(fmt.Sprintf("iptables -I INPUT -p tcp --dport %s -j REJECT --reject-with tcp-reset", p.Port)); err != nil {
		return err
	}

	for _, path := range p.Passports {
		if path.IP == "" {
			continue
		}
		if err := runIptables(fmt.Sprintf("iptables -I INPUT --source %s -p tcp --dport %s -j ACCEPT -m comment --comment %s", path.IP, p.Port, path.Name)); err != nil {
			return err
		}
		log.Printf("put ip %s in port %s whitelist name %s ", path.IP, p.Port, path.Name)
	}

	return nil
}

func (p *Captain) iptables() error {
	if err := runIptables("iptables -F"); err != nil {
		return err
	}
	for _, v := range p.Ports {
		if err := v.iptables(); err != nil {
			return err
		}
	}
	return p.guardSelf()
}

func (p *Captain) routes() error {
	for i := range p.Ports {
		for j, path := range p.Ports[i].Passports {
			r := fmt.Sprintf("/%s/%s", p.Ports[i].Port, path.Path)
			portIndex := i
			wayIndex := j
			http.HandleFunc(r, func(rw http.ResponseWriter, r *http.Request) {
				ip, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					rw.WriteHeader(http.StatusInternalServerError)
					rw.Write([]byte(err.Error()))
					return
				}
				if path.IP == ip {
					rw.Write([]byte(ip))
					return
				}
				// refactor this
				p.Ports[portIndex].Passports[wayIndex].IP = ip
				p.iptables()
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte(ip))
			})
		}
	}
	return nil
}

// route browser
func (p *Captain) routeIcon() error {
	http.HandleFunc("/favicon.ico", func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte("Hello, World!"))
	})
	return nil
}

func (p *Captain) route404() error {
	http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte(err.Error()))
			return
		}

		if p.Suspects[clientIP] == nil {
			p.Suspects[clientIP] = &Suspect{Time: time.Now(), Count: 1}
		} else {
			b := p.Suspects[clientIP]
			b.Count = b.Count + 1
			p.Suspects[clientIP] = b
		}
		p.iptables()
		rw.Write([]byte("Hello, World!"))
	})
	return nil
}

func (p *Captain) routeConfig() error {
	http.HandleFunc("/configs", func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
		json.NewEncoder(rw).Encode(p)
	})
	return nil
}

func (p *Captain) watchSuspects() {
	ticker := time.NewTicker(10 * time.Minute)
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := p.freeSuspects(); err != nil {
					os.Exit(1)
				}
			}
		}
	}()
}

func (p *Captain) freeSuspects() error {
	for k, v := range p.Suspects {
		// reset after 1 hr
		if time.Now().After(v.Time.Add(time.Hour)) {
			delete(p.Suspects, k)
		}

	}
	return p.iptables()
}

func (p *Captain) Run() error {
	p.loadConfig()
	p.Suspects = make(map[string]*Suspect)
	p.route404()
	p.routeIcon()
	p.routes()

	p.routeConfig()
	p.watchSuspects()
	log.Fatal(http.ListenAndServe("0.0.0.0:"+p.HTTPort, nil))
	return nil
}

func runIptables(command string) error {
	splitedCommands := strings.Split(command, " ")
	c := exec.Command("sudo", splitedCommands...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func (p *Captain) loadConfig() error {
	data, err := ioutil.ReadFile("guard.json")
	if err != nil {
		log.Panic(err)
	}
	return json.Unmarshal(data, &p)
}
