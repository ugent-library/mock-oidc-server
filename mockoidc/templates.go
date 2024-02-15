package mockoidc

import "html/template"

const templateAuthS = `
<!doctype html>
<html>
<head>
<style type="text/css">
dd, dt {
	padding: 5pt;
}
a.user-link {
	padding: 5pt;
	font-size: 16pt;
}
</style>
<script type="text/javascript">
window.addEventListener("load", () => {
	document.querySelectorAll('a.user-link').forEach(item => {
		item.addEventListener('click', evt => {
			evt.preventDefault()
			document.getElementsByName("username")[0].value = item.dataset.username;
			document.getElementById("auth-form").submit();
		})
	})
});
</script>
</head>
<body>
	<h1>Authenticate with user:</h1>
	{{with .Error}}
		<p><b>{{.}}</b></p>
	{{end}}
	<form method="POST" id="auth-form" action="{{.FormAction}}">
		<input name="username" type="hidden">
		<input type="hidden" name="scope" value="{{.Scope}}">
		<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
		<input type="hidden" name="state" value="{{.State}}">
		<input type="hidden" name="client_id" value="{{.ClientID}}">
		<input type="hidden" name="response_type" value="{{.ResponseType}}">
		<input type="hidden" name="nonce" value="{{.Nonce}}">
	</form>
	{{with .Users}}
		<dl>
		  {{range .}}
		  	<dt style="user-select:all">
				<a href="#" data-username="{{.ID}}" class="user-link">{{.ID}}</a>
			</dt>
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
	Nonce        string
	FormAction   string
}
