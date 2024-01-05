package mockoidc

import "html/template"

const templateAuthS = `
<!doctype html>
<html>
<body>
	<h1>Authenticate:</h1>
	{{with .Error}}
		<p><b>{{.}}</b></p>
	{{end}}
	<form method="POST">
		Username: <input name="username" type="text">
		<input type="hidden" name="scope" value="{{.Scope}}">
		<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
		<input type="hidden" name="state" value="{{.State}}">
		<input type="hidden" name="client_id" value="{{.ClientID}}">
		<input type="hidden" name="response_type" value="{{.ResponseType}}">
		<button type="submit">Submit</button>
	</form>
	<h1>Available users:</h1>
	{{with .Users}}
		<dl>
		  {{range .}}
		  	<dt style="user-select:all">{{.ID}}</dt>
			{{range .Claims}}
			<dd>{{.Name}} = <code style="user-select:all">{{.Value}}</code></dd>
			{{end}}
		  {{end}}
		  </tbody>
		</dl>
	{{else}}
		No users configured
	{{end}}
</body>
</html>
`

var templateAuth = template.Must(template.New("").Parse(templateAuthS))

type templateAuthParams struct {
	Username     string
	Scope        string
	RedirectURI  string
	State        string
	ClientID     string
	ResponseType string
	Error        string
	Users        []*User
}
