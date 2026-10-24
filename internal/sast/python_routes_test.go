package sast_test

import (
	"slices"
	"testing"
)

func TestPythonRoutePathParts(t *testing.T) {
	for _, tt := range []struct {
		name, setup, decorator, source, after string
		want                                  []string
	}{
		{"static route", "app = Flask(__name__)", "@app.route('/files/fixed')", "request.path.split('/')[1]", "open(value)", nil},
		{"static route local list", "app = Flask(__name__)", "@app.route('/files/fixed')", "parts[1]", "open(value)", nil},
		{"dynamic route", "app = Flask(__name__)", "@app.route('/<name>/fixed')", "request.path.split('/')[1]", "open(value)", []string{"sast:py/path-traversal"}},
		{"path converter", "app = Flask(__name__)", "@app.route('/<path:name>/fixed')", "request.path.split('/')[1]", "open(value)", []string{"sast:py/path-traversal"}},
		{"unknown route", "app = Flask(__name__)", "@app.route(pattern)", "request.path.split('/')[1]", "open(value)", []string{"sast:py/path-traversal"}},
		{"unknown router", "app = make_router()", "@app.route('/files/fixed')", "request.path.split('/')[1]", "open(value)", []string{"sast:py/path-traversal"}},
		{"router overwritten", "app = Flask(__name__)\napp = make_router()", "@app.route('/files/fixed')", "parts[1]", "open(value)", []string{"sast:py/path-traversal"}},
		{"router import overwrites binding", "app = Flask(__name__)\nfrom other import app", "@app.route('/files/fixed')", "parts[1]", "open(value)", []string{"sast:py/path-traversal"}},
		{"router changed by another function", "app = Flask(__name__)\ndef replace():\n    global app\n    app = make_router()", "@app.route('/files/fixed')", "parts[1]", "open(value)", []string{"sast:py/path-traversal"}},
		{"blueprint prefix", "app = Blueprint('files', __name__)", "@app.route('/files/fixed')", "request.path.split('/')[1]", "open(value)", []string{"sast:py/path-traversal"}},
		{"multiple different routes", "app = Flask(__name__)", "@app.route('/files/fixed')\n@app.route('/other/fixed')", "request.path.split('/')[1]", "open(value)", []string{"sast:py/path-traversal"}},
		{"query remains untrusted", "app = Flask(__name__)", "@app.route('/files/fixed')", "request.args['file']", "open(value)", []string{"sast:py/path-traversal"}},
		{"whole path remains conservative", "app = Flask(__name__)", "@app.route('/files/fixed')", "request.path", "open(value)", []string{"sast:py/path-traversal"}},
		{"different split", "app = Flask(__name__)", "@app.route('/files/fixed')", "request.path.split('?')[0]", "open(value)", []string{"sast:py/path-traversal"}},
		{"bounded split", "app = Flask(__name__)", "@app.route('/files/fixed')", "request.path.split('/', 1)[1]", "open(value)", []string{"sast:py/path-traversal"}},
		{"mutated path list", "app = Flask(__name__)", "@app.route('/files/fixed')", "parts[1]", "parts[1] = request.args['file']\n    open(parts[1])", []string{"sast:py/path-traversal"}},
		{"escaping path list", "app = Flask(__name__)", "@app.route('/files/fixed')", "parts[1]", "mutate(parts, request.args['file'])\n    open(parts[1])", []string{"sast:py/path-traversal"}},
		{"request path overwritten", "app = Flask(__name__)", "@app.route('/files/fixed')", "parts[1]", "request.path = request.args['file']\n    open(request.path.split('/')[1])", []string{"sast:py/path-traversal"}},
		{"request object escapes", "app = Flask(__name__)", "@app.route('/files/fixed')", "parts[1]", "mutate(request)\n    open(request.path.split('/')[1])", []string{"sast:py/path-traversal"}},
		{"helper rewrites request", "app = Flask(__name__)\ndef rewrite():\n    request.path = request.args['file']", "@app.route('/files/fixed')", "parts[1]", "rewrite()\n    open(request.path.split('/')[1])", []string{"sast:py/path-traversal"}},
		{"shell", "app = Flask(__name__)", "@app.route('/files/fixed')", "parts[1]", "os.system(value)", nil},
		{"xpath", "app = Flask(__name__)", "@app.route('/files/fixed')", "parts[1]", "tree.xpath(value)", nil},
		{"html", "app = Flask(__name__)", "@app.route('/files/fixed')", "parts[1]", "return '<p>' + value + '</p>'", nil},
		{"request shadowing", "app = Flask(__name__)", "@app.route('/files/fixed')", "parts[1]", "request = other\n    open(request.path.split('/')[1])", []string{"sast:py/path-traversal"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := "from flask import Flask, Blueprint, request\nimport os\n" + tt.setup + "\n" + tt.decorator + "\ndef route(tree, other):\n    parts = request.path.split('/')\n    value = " + tt.source + "\n    " + tt.after + "\n"
			if got := analyze(t, map[string]string{"app.py": src}); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPythonRouteRegistration(t *testing.T) {
	routes := `from flask import request
def register(router):
    @router.route('/files/fixed')
    def page():
        parts = request.path.split('/')
        open(parts[1])
`
	for _, tt := range []struct {
		name, main, extra string
		want              []string
	}{
		{"direct registrar", "from routes import register\nregister(app)", "", nil},
		{"dynamic module registrar", "import importlib\nfor module in plugins:\n    plugin = importlib.import_module(module)\n    plugin.register(app)", "", nil},
		{"literal module registrar", "import importlib\nplugin = importlib.import_module('routes')\nplugin.register(app)", "", nil},
		{"unknown argument", "from routes import register\nregister(unknown)", "", []string{"sast:py/path-traversal"}},
		{"unknown registrar callers", "", "", []string{"sast:py/path-traversal"}},
		{"mixed app and blueprint", "from routes import register\nregister(app)\nregister(Blueprint('plugin', __name__))", "", []string{"sast:py/path-traversal"}},
		{"mixed known and unknown arguments", "from routes import register\nregister(app)\nregister(unknown)", "", []string{"sast:py/path-traversal"}},
		{"registrar escapes", "from routes import register\nsaved = register\nregister(app)", "", []string{"sast:py/path-traversal"}},
		{"direct handler call with unknown path", "from routes import register\nregister(app)", "\ndef invoke():\n    page()\n", []string{"sast:py/path-traversal"}},
		{"handler escapes", "from routes import register\nregister(app)", "\ncallback = page\n", []string{"sast:py/path-traversal"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"main.py":   "from flask import Flask, Blueprint\napp = Flask(__name__)\n" + tt.main + "\n",
				"routes.py": routes + tt.extra,
			}
			if got := analyze(t, files); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
