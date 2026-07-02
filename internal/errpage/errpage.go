// Package errpage renders Coen's HTTP error responses as a minimal,
// self-contained HTML page (no external assets) and writes them to a stream.
// Both the edge and the agent use it so every error the client sees looks the
// same: the HTTP code, the reason, a short message, and a footer carrying the
// Coen name and the request's correlation id.
package errpage

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
)

var page = template.Must(template.New("err").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>{{.Code}} {{.Reason}}</title>
<style>
html,body{height:100%;margin:0}
body{display:flex;flex-direction:column;align-items:center;justify-content:center;
min-height:100%;box-sizing:border-box;padding:2rem;text-align:center;
font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
color:#111;background:#fff}
.code{font-size:5rem;font-weight:700;line-height:1;letter-spacing:-.02em}
.reason{font-size:1.5rem;color:#444;margin-top:.5rem}
.detail{font-size:1rem;color:#777;margin-top:1rem}
.footer{font-size:.8rem;color:#999;margin-top:2.5rem}
.footer .id{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
</style>
</head>
<body>
<div class="code">{{.Code}}</div>
<div class="reason">{{.Reason}}</div>
{{if .Detail}}<div class="detail">{{.Detail}}</div>{{end}}
<div class="footer">Coen &middot; conn <span class="id">{{.ConnID}}</span></div>
</body>
</html>
`))

type data struct {
	Code   int
	Reason string
	Detail string
	ConnID string
}

// Render returns the HTML body for an error page. detail may be empty.
func Render(code int, reason, detail, connID string) string {
	var b bytes.Buffer
	// Execute cannot fail for this fixed template and simple data.
	_ = page.Execute(&b, data{Code: code, Reason: reason, Detail: detail, ConnID: connID})
	return b.String()
}

// Write sends a complete HTTP/1.1 error response (status line, headers, and the
// HTML page) to w, with Connection: close.
func Write(w io.Writer, code int, reason, detail, connID string) {
	body := Render(code, reason, detail, connID)
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, reason, len(body), body)
}
