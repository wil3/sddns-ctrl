package main

import "net/http"

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route

var routes = Routes{
	Route{
		"Boot",
		"GET",
		"/rule/",
		GetBootNode,
	},
	Route{
		"Assign",
		"GET",
		"/rule/{clientToken}",
		GetRule,
	},

	Route{
		"Join",
		"POST",
		"/join",
		Join,
	},
	Route{
		"Alert",
		"GET",
		"/alert/{clientToken}",
		Alert,
	},
}
