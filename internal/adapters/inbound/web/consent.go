// Package web renders explicit view models without service lookup or I/O.
package web

import (
	"bytes"
	"html/template"
)

type Permission struct{ Name, Description string }
type Consent struct {
	ClientName, ResourceName, RedirectURI, CSRF, Action, LogoutAction string
	ClientID, ResourceURI                                             string
	Permissions                                                       []Permission
}

func ConsentPage(view Consent) ([]byte, error) {
	t, err := template.New("consent").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Approve access · Mayi</title></head><body><main><h1>Approve access</h1><p><strong>{{.ClientName}}</strong> is asking to access <strong>{{.ResourceName}}</strong>.</p><p>Tenant-registered client: <span>{{.ClientID}}</span>. API audience: <span>{{.ResourceURI}}</span>.</p><p>You will return to <span>{{.RedirectURI}}</span>.</p><ul>{{range .Permissions}}<li><strong>{{.Name}}</strong>: {{.Description}}</li>{{end}}</ul><form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><button name="decision" value="approve">Approve</button><button name="decision" value="deny">Deny</button></form><form method="post" action="{{.LogoutAction}}"><button>End this Mayi session</button></form></main></body></html>`)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = t.Execute(&out, view)
	return out.Bytes(), err
}
