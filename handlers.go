package main

import (
	"encoding/json"

	"github.com/gorilla/mux"
	"github.com/wil3/sddns"
	"net/http"
)

var defaultRule = sddns.Rule{
	ClientToken: "",
	Ipv4: "127.0.0.1",
	Ttl: 120,
	Timeout: 600,
}

func GetRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var rule sddns.Rule

	//TODO verify token

	//If there is no token the client just bootstrapped into the system
	if _, ok := vars["clientToken"]; ok {
		rule = defaultRule
	} else {
		//Do some logic to determine what IP address the client should be sent to
		rule = defaultRule
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(rule); err != nil {
		panic(err)
	}
	return

	// If we didn't find it, 404
	/*
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)
	if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusNotFound, Text: "Not Found"}); err != nil {
		panic(err)
	}
	*/

}

