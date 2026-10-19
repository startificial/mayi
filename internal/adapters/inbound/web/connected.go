package web

import (
	"bytes"
	"html/template"
)

type ConnectedGrant struct {
	ID, Client, Resource, Expires, LastIssued, LastUsed, RevokeAction string
	Permissions                                                       []string
	Objects                                                           []ConsentObject
	TokensIssued                                                      uint64
}
type ConnectedApps struct{ Grants []ConnectedGrant }

func ConnectedAppsPage(view ConnectedApps) ([]byte, error) {
	t, err := template.New("connected").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connected applications · Mayi</title></head><body><main><h1>Connected applications</h1><p>Revoking access stops the next fresh authorization decision. Signing out is a separate action.</p>{{range .Grants}}<section><h2>{{.Client}}</h2><p>API: {{.Resource}}. Expires: {{.Expires}}.</p><ul>{{range .Permissions}}<li>{{.}}</li>{{end}}</ul><ul>{{range .Objects}}<li>{{.Type}} / {{.Identifier}}: {{range .Actions}}{{.Name}} {{end}}</li>{{end}}</ul><p>Access tokens issued: {{.TokensIssued}}. Most recent issuance: {{.LastIssued}}. Last token use/check: {{if .LastUsed}}{{.LastUsed}}{{else}}Never{{end}}.</p><form method="post" action="{{.RevokeAction}}"><button>Revoke access</button></form></section>{{else}}<p>No active connected applications.</p>{{end}}</main></body></html>`)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = t.Execute(&out, view)
	return out.Bytes(), err
}
