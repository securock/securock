package typosquat

// The lists hold well-known package names, sorted so lookups can binary-search them.
// They are a heuristic reference, not an allowlist: a name that is not listed is
// simply not compared against.

var npmPopular = []string{
	"angular", "apollo-server", "archiver", "async", "autoprefixer", "axios", "babel-loader",
	"bcrypt", "bluebird", "body-parser", "bootstrap", "boxen", "chalk", "cheerio", "classnames",
	"colors", "commander", "compression", "concurrently", "cookie-parser", "core-js", "cors",
	"cross-env", "css-loader", "cypress", "date-fns", "dayjs", "debug", "dotenv", "ejs",
	"ember-cli", "esbuild", "eslint", "eventemitter3", "express", "express-session",
	"file-loader", "form-data", "fs-extra", "glob", "got", "graphql", "grunt", "gulp",
	"handlebars", "helmet", "husky", "immer", "inquirer", "isomorphic-fetch", "jest", "joi",
	"jquery", "jsdom", "jsonwebtoken", "knex", "left-pad", "lint-staged", "lodash", "lodash-es",
	"lodash.get", "lodash.merge", "mime", "minimist", "mkdirp", "mocha", "moment",
	"moment-timezone", "mongodb", "mongoose", "morgan", "ms", "multer", "mysql", "nanoid", "next",
	"node-fetch", "node-sass", "nodemailer", "nodemon", "ora", "passport", "pg", "pino",
	"playwright", "postcss", "prettier", "prop-types", "pug", "puppeteer", "qs", "ramda", "react",
	"react-dom", "react-redux", "react-router", "react-router-dom", "redis", "redux", "request",
	"rimraf", "rollup", "rxjs", "sass", "semver", "sequelize", "sharp", "socket.io",
	"socket.io-client", "sqlite3", "style-loader", "styled-components", "superagent", "svelte",
	"tailwindcss", "tar", "terser", "ts-jest", "ts-node", "tslib", "typeorm", "typescript",
	"uglify-js", "underscore", "uuid", "validator", "vite", "vue", "webpack", "webpack-cli",
	"webpack-dev-server", "whatwg-fetch", "winston", "ws", "yargs", "yup", "zod",
}

var pypiPopular = []string{
	"aiohttp", "aiosignal", "ansible", "async-timeout", "attrs", "awscli", "azure-core", "bcrypt",
	"beautifulsoup4", "black", "bokeh", "boto3", "botocore", "cachetools", "celery", "certifi",
	"cffi", "chardet", "charset-normalizer", "click", "colorama", "coverage", "cryptography",
	"cython", "decorator", "django", "docker", "docutils", "fabric", "factory-boy", "faker",
	"fastapi", "filelock", "flake8", "flask", "frozenlist", "gevent", "google-auth", "greenlet",
	"grpcio", "gunicorn", "h5py", "httpx", "idna", "importlib-metadata", "ipython",
	"itsdangerous", "jaraco-classes", "jinja2", "jmespath", "jsonschema", "jupyter", "keras",
	"kubernetes", "lxml", "markdown", "markupsafe", "matplotlib", "mock", "more-itertools",
	"multidict", "mypy", "networkx", "nltk", "nose", "notebook", "numba", "numpy", "oauthlib",
	"opencv-python", "openpyxl", "orjson", "packaging", "pandas", "paramiko", "passlib",
	"pexpect", "pillow", "pip", "platformdirs", "plotly", "protobuf", "psutil", "psycopg2",
	"pyarrow", "pyasn1", "pycparser", "pydantic", "pygments", "pyjwt", "pylint", "pymongo",
	"pyopenssl", "pyparsing", "pyserial", "pytest", "pytest-cov", "pytest-mock",
	"python-dateutil", "python-dotenv", "pytz", "pyyaml", "redis", "regex", "requests",
	"requests-oauthlib", "rich", "rsa", "s3transfer", "scikit-learn", "scipy", "seaborn",
	"selenium", "setuptools", "simplejson", "six", "spacy", "sphinx", "sqlalchemy", "statsmodels",
	"sympy", "tensorflow", "toml", "tomli", "torch", "tornado", "tox", "tqdm", "transformers",
	"twisted", "typer", "typing-extensions", "ujson", "urllib3", "uvicorn", "virtualenv",
	"werkzeug", "wheel", "wrapt", "xlrd", "yarl", "zipp",
}
