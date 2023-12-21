package main

import "html/template"

const templateAuthS = `
<!doctype html>
<html>
<body>
	{{with .Error}}
		<p><b>{{.}}</b></p>
	{{end}}
	<form method="POST" action="{{.FormAction}}">
		Username: <input name="username" type="text">
		<input type="hidden" name="scope" value="{{.Scope}}">
		<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
		<input type="hidden" name="state" value="{{.State}}">
		<input type="hidden" name="client_id" value="{{.ClientID}}">
		<input type="hidden" name="response_type" value="{{.ResponseType}}">
	</form>
</body>
</html>
`

var templateAuth = template.Must(template.New("").Parse(templateAuthS))

type templateAuthParams struct {
	FormAction   string
	Username     string
	Scope        string
	RedirectURI  string
	State        string
	ClientID     string
	ResponseType string
	Error        string
}
