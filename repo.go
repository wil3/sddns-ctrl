package main

var Nodes []Node

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
