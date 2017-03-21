package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	//	"encoding/binary"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/wil3/sddns"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

type HoneyApp struct {
	RealServer  Node
	HoneyServer Node
}

var MyHoneyApp = HoneyApp{}

var defaultRule = sddns.Rule{
	ClientToken: "",
	Ipv4:        "",
	Ttl:         0,
	Timeout:     600,
}
var LEN_IV = 12
var LEN_TAG = 16

func GetBootNode(w http.ResponseWriter, r *http.Request) {
	//Do some logic to determine what IP address the client should be sent to

	log.Println("Client doesnt have token")

	rand.Seed(time.Now().Unix())
	nodeIPs := RepoGetAllIPs()
	if len(nodeIPs) == 0 {
		log.Fatal("No nodes have joined yet!")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	dstIP := nodeIPs[rand.Intn(len(nodeIPs))]
	var rule sddns.Rule
	rule = defaultRule
	rule.Ipv4 = dstIP

	respondWithRule(w, rule)
	return
}

// Alert from one of the nodes
//
func Alert(w http.ResponseWriter, r *http.Request) {
	log.Println("Received alert")

	vars := mux.Vars(r)
	token := vars["clientToken"]
	_, id, err := parseToken(token)
	if err != nil {
		log.Fatalf("Could not parse token %v", err)
		http.NotFound(w, r)
		return
	}

	if c, ok := ClientAssignments[id]; ok {
		messageNode(c.AssignedNode, c, "block")
		c.AssignedNode = MyHoneyApp.HoneyServer
		log.Printf("Reassigning client to server \"%s\"", c.AssignedNode.Host)

	} else {
		log.Println("There is no assignment for \"%s\"", id)
	}
}

//GET request
func GetRule(w http.ResponseWriter, r *http.Request) {
	if len(Nodes) == 0 {
		log.Fatal("No nodes have joined yet!")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	//Vars are the tokens in the URL we specify in routes
	vars := mux.Vars(r)
	var rule sddns.Rule

	domain := vars["clientToken"]

	log.Printf("Domain received \"%s\"", domain)
	if strings.Compare(domain, Context.AppDomain) == 0 {
		//Boot
		log.Println("Booting client")
		GetBootNode(w, r)
		return
	}

	labels := strings.Split(domain, ".")
	log.Printf("label len: %d token len: %d", len(labels), Context.DomainTokenLen)
	if len(labels)-1 != Context.DomainTokenLen {
		log.Println("Not found")
		http.NotFound(w, r)
		return
	}
	token := labels[0]
	log.Printf("Labels %v\n", labels)
	log.Printf("Client has token \"%s\"", token)

	//FIXME Remove me this is only for benchmarking
	//So we can bypass cache
	if len(token) == 10 {
		//Magic number
		log.Println("Booting client for benchmark")
		GetBootNode(w, r)
		return

	}

	if len(token) < 61 {
		log.Println("The token is too short")
		http.NotFound(w, r)
		return

	}

	ip, id, err := parseToken(token)
	if err != nil {
		log.Fatalf("Could not parse token %v", err)
		http.NotFound(w, r)
		return
	}

	//If there is no token the client just bootstrapped into the system
	//if _, ok := vars["clientToken"]; ok {
	log.Printf("IP \"%s\" ID \"%s\"", ip, id)

	//Check if there is already an assignment
	var targetNode Node
	var c *Client
	if val, ok := ClientAssignments[id]; ok {
		log.Printf("Already have an assignment for \"%s\", with host \"%s\"", id, val.AssignedNode.Host)
		targetNode = val.AssignedNode
		c = val
	} else {
		log.Println("No assignment, using default")
		rule = defaultRule
		targetNode = MyHoneyApp.RealServer
		c = &Client{ID: id, IP: ip, AssignedNode: targetNode}
		ClientAssignments[id] = c
	}
	rule.Ipv4 = targetNode.IP
	messageNode(targetNode, c, "allow")
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

/**
 * Return the ip, id or error if something went wrong
 */
func parseToken(token string) (string, string, error) {

	base16 := base36to16(token)
	log.Printf("B16 %d: %s", hex.DecodedLen(len(base16)), base16)
	b := make([]byte, hex.DecodedLen(len(base16)))
	n, err := hex.Decode(b, []byte(base16))
	if err != nil {
		return "", "", err
	}
	log.Printf("Hex token\n %s", hex.Dump(b[:n]))

	iv := b[:LEN_IV]
	tag := b[LEN_IV : LEN_IV+LEN_TAG]
	ciphertext := b[LEN_IV+LEN_TAG:]

	ctAndTag := append(ciphertext, tag...)

	log.Printf("IV %s TAG %s CT %s", hex.Dump(iv), hex.Dump(tag), hex.Dump(ciphertext))
	plaintext, err := decryptToken([]byte(Context.Key), iv, ctAndTag)
	if err != nil {
		return "", "", err
	}

	log.Printf("Plaintext %s", hex.Dump(plaintext))

	id := base64.StdEncoding.EncodeToString(plaintext[4:])

	var ip net.IP
	ip = plaintext[:4]
	//ip := make(net.IP, 4)

	//binary.BigEndian.PutUint32(ip, nn)

	return ip.String(), id, nil
}

//TODO The DNS requests are asynchronised, to reduce load on the node, we should
//track if a request has been made so it isnt repeated.

/*
 * This is where we till the agent that they should accept this request
 * Reading posts in nginx was causing trouble so data is sent as a GET
 */
func messageNode(n Node, c *Client, action string) {

	url := fmt.Sprintf("http://%s", n.Host)
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	q := req.URL.Query()
	q.Add("action", action)
	q.Add("id", c.ID)
	q.Add("ip", c.IP)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Origin", Context.Domain)

	mac := hmac.New(sha256.New, []byte(Context.Key))
	message := fmt.Sprintf("%s%s", "GET", q.Encode())
	log.Printf("Message to be signed \"%s\"", message)
	mac.Write([]byte(message))

	req.Header.Set("Authorization", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error messaging node %v", err)
	}
	log.Printf("Response from node %d", res.StatusCode)
}
func respondWithRule(w http.ResponseWriter, rule sddns.Rule) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(rule); err != nil {
		panic(err)
	}
}

func base36to16(s string) string {
	i := new(big.Int)
	i.SetString(s, 36)
	b16 := i.Text(16)
	if len(b16)%2 != 0 {
		return "0" + b16
	}
	return b16
}

func decryptToken(key []byte, iv []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, LEN_IV)
	if err != nil {
		return nil, err
	}
	//This package wants the tag part of the ciphertext
	//such that the tag is appended
	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func Join(w http.ResponseWriter, r *http.Request) {
	log.Println("Join request")
	r.ParseForm()
	pk := r.Form.Get("pk")
	host := r.Form.Get("host")
	//TODO verify request
	ip := strings.Split(r.RemoteAddr, ":")[0]
	log.Printf("Server joined: Remote address %s\t Host:\"%s\"\t PK:%s\n", ip, host, pk)
	var n = Node{IP: ip, Host: host, PK: pk}
	RepoInsertNode(n)

	//Set the first joined server as the real server
	if (HoneyApp{}) == MyHoneyApp {
		MyHoneyApp.RealServer = n
		log.Println("Setting joined server as app server")
	} else {
		MyHoneyApp.HoneyServer = n
		log.Println("Setting joined server as honey server")
	}
	return
}
