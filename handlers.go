package main

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	//	"crypto/aes"
	//	"crypto/cipher"
	"github.com/gorilla/mux"
	"github.com/wil3/sddns"
	"math/big"
	"math/rand"
	"net/http"
)

var defaultRule = sddns.Rule{
	ClientToken: "",
	Ipv4:        "",
	Ttl:         120,
	Timeout:     600,
}

func GetBootNode(w http.ResponseWriter, r *http.Request) {
	//Do some logic to determine what IP address the client should be sent to

	log.Println("Client doesnt have token")

	rand.Seed(time.Now().Unix())
	nodeIPs := RepoGetAllIPs()
	if len(nodeIPs) == 0 {
		panic("No nodes have joined yet!")
	}

	dstIP := nodeIPs[rand.Intn(len(nodeIPs))]
	var rule sddns.Rule
	rule = defaultRule
	rule.Ipv4 = dstIP

	log.Printf("Decode %s\n", base36decode("xpm"))

	respondWithRule(w, rule)
	return
}

//GET request
func GetRule(w http.ResponseWriter, r *http.Request) {
	//Vars are the tokens in the URL we specify in routes
	vars := mux.Vars(r)
	var rule sddns.Rule

	//TODO verify token

	//If there is no token the client just bootstrapped into the system
	//if _, ok := vars["clientToken"]; ok {
	log.Printf("Client has token \"%s\"", vars["clientToken"])

	//	decryptToken(vars["clientToken"])
	rule = defaultRule
	rule.Ipv4 = RepoGetAllIPs()[0]
	notifyNode()
	respondWithRule(w, rule)
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

/*
 * This is where we till the agent that they should accept this request
 */
func notifyNode() {

}
func respondWithRule(w http.ResponseWriter, rule sddns.Rule) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(rule); err != nil {
		panic(err)
	}
}
func base36decode(s string) string {
	i := new(big.Int)
	i.SetString(s, 16)

	return i.Text(36)
}

/*
func decryptToken(token string) (ip string, id string, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
}
*/
func Join(w http.ResponseWriter, r *http.Request) {
	log.Println("Join request")
	//TODO verify request
	ip := strings.Split(r.RemoteAddr, ":")[0]
	log.Printf("Remote address %s\n", ip)
	var n = Node{IP: ip}
	RepoInsertNode(n)
	return
}
