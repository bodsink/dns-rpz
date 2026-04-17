package api

import (
	"html/template"
	"net/http"
	"path/filepath"
	"sync"

	"github.com/gin-gonic/gin/render"
)

// tmplRenderer is a custom Gin HTML renderer that parses base.html +
// the specific page template together for each unique page name.
// This prevents Go template's shared {{define "content"}} from being
// overwritten by the last-parsed template (LoadHTMLGlob bug).
type tmplRenderer struct {
	dir     string
	funcMap template.FuncMap
	mu      sync.RWMutex
	cache   map[string]*template.Template
}

func newRenderer(dir string, funcMap template.FuncMap) *tmplRenderer {
	return &tmplRenderer{
		dir:     dir,
		funcMap: funcMap,
		cache:   make(map[string]*template.Template),
	}
}

func (r *tmplRenderer) Instance(name string, data any) render.Render {
	return &tmplInstance{renderer: r, name: name, data: data}
}

func (r *tmplRenderer) get(name string) (*template.Template, error) {
	r.mu.RLock()
	if t, ok := r.cache[name]; ok {
		r.mu.RUnlock()
		return t, nil
	}
	r.mu.RUnlock()

	var (
		t   *template.Template
		err error
	)

	base := filepath.Join(r.dir, "base.html")
	page := filepath.Join(r.dir, name)

	// Partials (zone_row.html etc.) do not extend base — parse standalone.
	// Full pages extend base — parse both together so "content" block is isolated.
	if isPartial(name) {
		t, err = template.New("").Funcs(r.funcMap).ParseFiles(page)
	} else {
		// Parse base.html + the page template together so each pair has its own
		// isolated "content" block definition — no cross-page contamination.
		t, err = template.New("").Funcs(r.funcMap).ParseFiles(base, page)
	}
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.cache[name] = t
	r.mu.Unlock()
	return t, nil
}

// isPartial returns true for templates that don't extend base.html.
func isPartial(name string) bool {
	partials := map[string]bool{
		"zone_row.html": true,
	}
	return partials[name]
}

type tmplInstance struct {
	renderer *tmplRenderer
	name     string
	data     any
}

func (i *tmplInstance) Render(w http.ResponseWriter) error {
	i.WriteContentType(w)
	t, err := i.renderer.get(i.name)
	if err != nil {
		return err
	}
	return t.ExecuteTemplate(w, i.name, i.data)
}

func (i *tmplInstance) WriteContentType(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}
