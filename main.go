package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
)

type Config struct {
	Key            string
	Port           int
	Domain         string
	DomainTokenLen int
	AppDomain      string
}

var Context = Config{}

func main() {

	data, err := ioutil.ReadFile("ctrl.conf")
	if err != nil {
		log.Fatalf("Could not read config file: %v", err)
		return
	}

	err = yaml.Unmarshal(data, &Context)
	if err != nil {
		log.Fatalf("Could not unmarshal config: %v", err)
	}
	router := NewRouter()

	port := fmt.Sprintf(":%d", Context.Port)
	log.Printf("This servers domain is \"%s\"", Context.Domain)
	log.Printf("Listening on port %d", Context.Port)
	log.Printf("Token length %d", Context.DomainTokenLen)
	log.Printf("App Domain %s", Context.AppDomain)
	log.Fatal(http.ListenAndServe(port, router))
}
