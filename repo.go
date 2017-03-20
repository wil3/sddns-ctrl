package main

var Nodes []Node

type Client struct {
	ID           string
	IP           string
	AssignedNode Node
}

var ClientAssignments = make(map[string]*Client)

func RepoInsertNode(node Node) {
	Nodes = append(Nodes, node)
}

func RepoGetAllIPs() []string {
	var ips []string
	for _, node := range Nodes {
		ips = append(ips, node.IP)
	}
	return ips
}
