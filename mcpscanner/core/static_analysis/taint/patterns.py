# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Comprehensive taint patterns for all supported languages.

Security patterns for:
- Command injection (CWE-78)
- SQL injection (CWE-89)
- Code injection / eval (CWE-94, CWE-95)
- Path traversal (CWE-22, CWE-23)
- SSRF (CWE-918)
- Deserialization (CWE-502)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class TaintPatterns:
    """Language-specific taint source, sink, and sanitizer patterns."""
    
    # =========================================================================
    # TAINT SOURCES - Where user input enters the system
    # =========================================================================
    
    # Python sources
    PYTHON_SOURCES: Set[str] = field(default_factory=lambda: {
        # Function parameters (handled separately)
        # Flask/Django request objects
        "request.args", "request.form", "request.data", "request.json",
        "request.values", "request.files", "request.cookies", "request.headers",
        "request.GET", "request.POST", "request.body",
        # AWS Lambda
        "event",
        # stdin
        "input", "sys.stdin", "raw_input",
        # Environment
        "os.environ", "os.getenv",
    })
    
    # JavaScript/TypeScript sources
    JS_SOURCES: Set[str] = field(default_factory=lambda: {
        # Express.js
        "req.query", "req.body", "req.params", "req.cookies", "req.headers",
        "request.query", "request.body", "request.params",
        # AWS Lambda
        "event",
        # Browser
        "window.location", "document.location", "location.href",
        "document.URL", "document.referrer",
        "localStorage", "sessionStorage",
        # URL params
        "URLSearchParams",
    })
    
    # Go sources
    GO_SOURCES: Set[str] = field(default_factory=lambda: {
        # http.Request
        "Request.Body", "Request.Form", "Request.PostForm", "Request.URL",
        "Request.Header", "Request.Cookie", "Request.Cookies",
        "Request.FormValue", "Request.PostFormValue", "Request.URL.Query",
        "Request.BasicAuth", "Request.Referer", "Request.UserAgent",
        "Request.Host", "Request.RequestURI",
        # Gin
        "Context.Query", "Context.PostForm", "Context.Param",
        # Environment
        "os.Getenv",
    })
    
    # Java sources
    JAVA_SOURCES: Set[str] = field(default_factory=lambda: {
        # Servlet
        "HttpServletRequest.getParameter", "HttpServletRequest.getParameterValues",
        "HttpServletRequest.getQueryString", "HttpServletRequest.getHeader",
        "HttpServletRequest.getCookies", "HttpServletRequest.getInputStream",
        "HttpServletRequest.getReader",
        # Spring
        "@RequestBody", "@PathVariable", "@RequestParam", "@RequestHeader",
        "@CookieValue", "@ModelAttribute",
        # AWS Lambda
        "APIGatewayProxyRequestEvent",
    })
    
    # Ruby sources
    RUBY_SOURCES: Set[str] = field(default_factory=lambda: {
        # Rails
        "params", "request.params", "request.body",
        "cookies", "request.cookies",
        "request.headers", "request.env",
        # Sinatra
        "params", "request",
    })
    
    # PHP sources
    PHP_SOURCES: Set[str] = field(default_factory=lambda: {
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES",
        "$_SERVER", "$_ENV",
        "file_get_contents('php://input')",
        "php://input",
    })
    
    # C# sources
    CSHARP_SOURCES: Set[str] = field(default_factory=lambda: {
        # ASP.NET
        "Request.QueryString", "Request.Form", "Request.Cookies",
        "Request.Headers", "Request.Body", "Request.Path",
        # MVC
        "[FromBody]", "[FromQuery]", "[FromRoute]", "[FromForm]",
    })
    
    # Rust sources (function parameters primarily)
    RUST_SOURCES: Set[str] = field(default_factory=lambda: {
        # Actix-web
        "web::Query", "web::Form", "web::Path", "web::Json",
        # Rocket
        "Form", "Query",
    })
    
    # =========================================================================
    # TAINT SINKS - Dangerous functions that should not receive tainted data
    # =========================================================================
    
    # Command injection sinks
    COMMAND_SINKS: Dict[str, Set[str]] = field(default_factory=lambda: {
        "python": {
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_output", "subprocess.check_call",
            "subprocess.getoutput", "subprocess.getstatusoutput",
            "os.system", "os.popen", "os.spawn", "os.spawnl", "os.spawnle",
            "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve",
            "os.spawnvp", "os.spawnvpe", "os.exec", "os.execl", "os.execle",
            "os.execlp", "os.execlpe", "os.execv", "os.execve", "os.execvp",
            "os.execvpe",
            "commands.getoutput", "commands.getstatusoutput",
            "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec",
        },
        "javascript": {
            "child_process.exec", "child_process.execSync",
            "child_process.spawn", "child_process.spawnSync",
            "child_process.execFile", "child_process.execFileSync",
            "child_process.fork",
            "exec", "execSync", "spawn", "spawnSync",
        },
        "go": {
            "exec.Command", "exec.CommandContext",
            "os.StartProcess", "syscall.Exec",
        },
        "java": {
            "Runtime.exec", "Runtime.getRuntime().exec",
            "ProcessBuilder.command", "ProcessBuilder.start",
            "Process",
        },
        "ruby": {
            "system", "exec", "spawn", "`", "Kernel.system", "Kernel.exec",
            "Kernel.spawn", "Kernel.`",
            "IO.popen", "Open3.capture2", "Open3.capture2e", "Open3.capture3",
            "Open3.popen2", "Open3.popen2e", "Open3.popen3",
            "Process.spawn", "Process.exec", "PTY.spawn",
            "Gem::Util.popen",
        },
        "php": {
            "exec", "system", "passthru", "shell_exec", "popen", "proc_open",
            "pcntl_exec", "expect_popen",
            "`",  # backticks
        },
        "csharp": {
            "Process.Start", "ProcessStartInfo",
            "System.Diagnostics.Process.Start",
        },
        "rust": {
            "Command::new", "std::process::Command",
        },
    })
    
    # SQL injection sinks
    SQL_SINKS: Dict[str, Set[str]] = field(default_factory=lambda: {
        "python": {
            "cursor.execute", "cursor.executemany",
            "connection.execute", "engine.execute",
            "session.execute", "db.execute",
            "raw", "RawSQL", "extra",
        },
        "javascript": {
            "query", "execute", "raw",
            "sequelize.query", "knex.raw",
            "connection.query", "pool.query",
        },
        "go": {
            "db.Query", "db.QueryRow", "db.Exec",
            "tx.Query", "tx.QueryRow", "tx.Exec",
            "stmt.Query", "stmt.QueryRow", "stmt.Exec",
        },
        "java": {
            "Statement.execute", "Statement.executeQuery", "Statement.executeUpdate",
            "Connection.prepareStatement", "Connection.createStatement",
            "JdbcTemplate.query", "JdbcTemplate.update",
            "EntityManager.createNativeQuery",
        },
        "ruby": {
            "execute", "exec_query", "select_all", "select_one",
            "find_by_sql", "count_by_sql",
            "ActiveRecord::Base.connection.execute",
        },
        "php": {
            "mysql_query", "mysqli_query", "pg_query",
            "PDO::query", "PDO::exec",
            "$pdo->query", "$pdo->exec",
            "$mysqli->query",
        },
        "csharp": {
            "SqlCommand", "ExecuteReader", "ExecuteNonQuery", "ExecuteScalar",
            "SqlDataAdapter",
        },
    })
    
    # Code injection / eval sinks
    EVAL_SINKS: Dict[str, Set[str]] = field(default_factory=lambda: {
        "python": {
            "eval", "exec", "compile",
            "ast.literal_eval",  # safer but still worth tracking
            "__import__", "importlib.import_module",
        },
        "javascript": {
            "eval", "Function", "new Function",
            "setTimeout", "setInterval",  # when passed strings
            "vm.runInContext", "vm.runInNewContext", "vm.runInThisContext",
        },
        "go": {},  # Go doesn't have eval
        "java": {
            "ScriptEngine.eval", "Interpreter.eval",
            "GroovyShell.evaluate", "GroovyShell.parse",
        },
        "ruby": {
            "eval", "instance_eval", "class_eval", "module_eval",
            "Kernel.eval", "binding.eval",
            "send", "public_send", "__send__",
        },
        "php": {
            "eval", "assert", "create_function",
            "preg_replace",  # with /e modifier
            "call_user_func", "call_user_func_array",
        },
        "csharp": {
            "CSharpCodeProvider.CompileAssemblyFromSource",
            "Assembly.Load",
        },
        "rust": {},  # Rust doesn't have eval
    })
    
    # File operation sinks (path traversal)
    FILE_SINKS: Dict[str, Set[str]] = field(default_factory=lambda: {
        "python": {
            "open", "file",
            "os.open", "os.read", "os.write",
            "io.open", "io.FileIO",
            "pathlib.Path.open", "pathlib.Path.read_text", "pathlib.Path.read_bytes",
            "pathlib.Path.write_text", "pathlib.Path.write_bytes",
            "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move",
            "os.remove", "os.unlink", "os.rmdir", "os.makedirs",
            "tarfile.open", "zipfile.ZipFile",
        },
        "javascript": {
            "fs.readFile", "fs.readFileSync", "fs.writeFile", "fs.writeFileSync",
            "fs.appendFile", "fs.appendFileSync",
            "fs.unlink", "fs.unlinkSync", "fs.rmdir", "fs.rmdirSync",
            "fs.mkdir", "fs.mkdirSync",
            "fs.createReadStream", "fs.createWriteStream",
            "fs.promises.readFile", "fs.promises.writeFile",
        },
        "go": {
            "os.Open", "os.OpenFile", "os.Create", "os.ReadFile", "os.WriteFile",
            "ioutil.ReadFile", "ioutil.WriteFile", "ioutil.ReadAll",
            "io.ReadAll", "io.Copy",
            "filepath.Join",  # can be safe if validated
        },
        "java": {
            "File", "FileReader", "FileWriter", "FileInputStream", "FileOutputStream",
            "BufferedReader", "BufferedWriter",
            "Files.readAllBytes", "Files.readAllLines", "Files.write",
            "Files.copy", "Files.move", "Files.delete",
            "Paths.get", "Path.of",
            "ClassPathResource", "ResourceUtils.getFile",
        },
        "ruby": {
            "File.open", "File.read", "File.write", "File.delete",
            "File.new", "File.binread", "File.binwrite",
            "IO.read", "IO.write", "IO.binread", "IO.binwrite",
            "FileUtils.cp", "FileUtils.mv", "FileUtils.rm",
        },
        "php": {
            "file_get_contents", "file_put_contents", "file",
            "fopen", "fread", "fwrite", "fgets", "fgetc",
            "readfile", "include", "include_once", "require", "require_once",
            "unlink", "rmdir", "mkdir",
            "copy", "rename", "move_uploaded_file",
        },
        "csharp": {
            "File.ReadAllText", "File.ReadAllTextAsync", "File.ReadAllBytes",
            "File.ReadAllLines", "File.WriteAllText", "File.WriteAllBytes",
            "File.Open", "File.OpenRead", "File.OpenWrite",
            "FileStream", "StreamReader", "StreamWriter",
            "Path.Combine",  # can be safe if validated
        },
        "rust": {
            "fs::read", "fs::read_to_string", "fs::write",
            "fs::File::open", "fs::File::create",
            "std::fs::read", "std::fs::write",
        },
    })
    
    # Network / SSRF sinks
    NETWORK_SINKS: Dict[str, Set[str]] = field(default_factory=lambda: {
        "python": {
            "requests.get", "requests.post", "requests.put", "requests.delete",
            "requests.patch", "requests.head", "requests.options",
            "urllib.request.urlopen", "urllib.request.Request",
            "urllib2.urlopen", "urllib2.Request",
            "httplib.HTTPConnection", "httplib.HTTPSConnection",
            "http.client.HTTPConnection", "http.client.HTTPSConnection",
            "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
            "httpx.get", "httpx.post", "httpx.AsyncClient",
        },
        "javascript": {
            "fetch", "axios.get", "axios.post", "axios.put", "axios.delete",
            "http.get", "http.request", "https.get", "https.request",
            "XMLHttpRequest", "$.ajax", "$.get", "$.post",
            "request", "got", "node-fetch",
        },
        "go": {
            "http.Get", "http.Post", "http.PostForm",
            "http.NewRequest", "http.Client.Do", "http.Client.Get",
            "net.Dial", "net.DialTCP", "net.DialUDP",
        },
        "java": {
            "URL.openConnection", "URL.openStream",
            "HttpURLConnection", "HttpsURLConnection",
            "HttpClient.send", "HttpClient.sendAsync",
            "RestTemplate.getForObject", "RestTemplate.postForObject",
            "WebClient.get", "WebClient.post",
        },
        "ruby": {
            "Net::HTTP.get", "Net::HTTP.post", "Net::HTTP.start",
            "open-uri", "OpenURI.open_uri",
            "HTTParty.get", "HTTParty.post",
            "RestClient.get", "RestClient.post",
            "Faraday.get", "Faraday.post",
        },
        "php": {
            "file_get_contents",  # with URL
            "curl_exec", "curl_init", "curl_setopt",
            "fopen",  # with URL
            "fsockopen", "pfsockopen",
            "stream_socket_client",
        },
        "csharp": {
            "HttpClient.GetAsync", "HttpClient.PostAsync",
            "HttpClient.GetStringAsync", "HttpClient.SendAsync",
            "WebClient.DownloadString", "WebClient.DownloadData",
            "WebRequest.Create", "HttpWebRequest",
        },
        "rust": {
            "reqwest::get", "reqwest::Client::get", "reqwest::Client::post",
            "hyper::Client::get",
        },
    })
    
    # Deserialization sinks
    DESERIALIZATION_SINKS: Dict[str, Set[str]] = field(default_factory=lambda: {
        "python": {
            "pickle.load", "pickle.loads",
            "cPickle.load", "cPickle.loads",
            "yaml.load", "yaml.unsafe_load",
            "marshal.load", "marshal.loads",
            "shelve.open",
        },
        "javascript": {
            "JSON.parse",  # generally safe but track
            "serialize-javascript",
            "node-serialize",
        },
        "go": {
            "gob.Decode", "gob.NewDecoder",
            "json.Unmarshal",  # generally safe
        },
        "java": {
            "ObjectInputStream.readObject",
            "XMLDecoder.readObject",
            "XStream.fromXML",
            "ObjectMapper.readValue",  # Jackson - can be unsafe
        },
        "ruby": {
            "Marshal.load", "Marshal.restore",
            "YAML.load", "YAML.unsafe_load",
        },
        "php": {
            "unserialize",
            "json_decode",  # generally safe
        },
        "csharp": {
            "BinaryFormatter.Deserialize",
            "SoapFormatter.Deserialize",
            "ObjectStateFormatter.Deserialize",
            "LosFormatter.Deserialize",
            "NetDataContractSerializer.Deserialize",
            "JsonConvert.DeserializeObject",  # Newtonsoft with TypeNameHandling
        },
        "rust": {
            "serde_json::from_str",  # generally safe
        },
    })
    
    # =========================================================================
    # SANITIZERS - Functions that make tainted data safe
    # =========================================================================
    
    SANITIZERS: Dict[str, Set[str]] = field(default_factory=lambda: {
        "python": {
            # Command
            "shlex.quote", "shlex.split", "pipes.quote",
            # SQL
            "parameterized", "prepared",
            # Path
            "os.path.basename", "os.path.normpath",
            "pathlib.Path.resolve",
            # HTML
            "html.escape", "markupsafe.escape",
            # Type conversion
            "int", "float", "bool",
        },
        "javascript": {
            # SQL
            "escape", "mysql.escape",
            # HTML
            "encodeURIComponent", "encodeURI",
            "DOMPurify.sanitize",
            # Type conversion
            "parseInt", "parseFloat", "Number",
        },
        "go": {
            # Type conversion
            "strconv.Atoi", "strconv.ParseInt", "strconv.ParseFloat",
            # Path
            "filepath.Clean", "filepath.Base",
            # HTML
            "html.EscapeString",
        },
        "java": {
            # Path
            "FilenameUtils.getName",
            "Paths.get().normalize()",
            # HTML
            "StringEscapeUtils.escapeHtml",
            "HtmlUtils.htmlEscape",
            # Type conversion
            "Integer.parseInt", "Long.parseLong",
        },
        "ruby": {
            # Command
            "Shellwords.escape", "Shellwords.shellescape",
            # HTML
            "ERB::Util.html_escape", "CGI.escapeHTML",
            # SQL - parameterized queries
            "sanitize_sql",
        },
        "php": {
            # Command
            "escapeshellcmd", "escapeshellarg",
            # SQL
            "mysqli_real_escape_string", "PDO::quote",
            # HTML
            "htmlspecialchars", "htmlentities",
            # Path
            "basename", "realpath",
        },
        "csharp": {
            # HTML
            "HttpUtility.HtmlEncode", "WebUtility.HtmlEncode",
            # Path
            "Path.GetFileName",
            # Type conversion
            "int.Parse", "int.TryParse",
        },
        "rust": {
            # Type conversion (Rust is generally safe due to type system)
            "parse",
        },
    })


# Global instance
TAINT_PATTERNS = TaintPatterns()


def get_sinks_for_language(language: str, category: str) -> Set[str]:
    """Get sink patterns for a language and category.
    
    Args:
        language: Language name (python, javascript, go, java, ruby, php, csharp, rust, kotlin)
        category: Sink category (command, sql, eval, file, network, deserialization)
    
    Returns:
        Set of sink function/method names
    """
    lang = language.lower()
    if lang in ("typescript", "tsx"):
        lang = "javascript"
    elif lang == "c_sharp":
        lang = "csharp"
    elif lang == "kotlin":
        lang = "java"  # Kotlin uses JVM, same sinks as Java
    
    category_map = {
        "command": TAINT_PATTERNS.COMMAND_SINKS,
        "sql": TAINT_PATTERNS.SQL_SINKS,
        "eval": TAINT_PATTERNS.EVAL_SINKS,
        "file": TAINT_PATTERNS.FILE_SINKS,
        "network": TAINT_PATTERNS.NETWORK_SINKS,
        "deserialization": TAINT_PATTERNS.DESERIALIZATION_SINKS,
    }
    
    sinks = category_map.get(category, {})
    return sinks.get(lang, set())


def get_all_sinks_for_language(language: str) -> Dict[str, Set[str]]:
    """Get all sink patterns for a language.
    
    Returns:
        Dict mapping category to set of sink names
    """
    return {
        "command": get_sinks_for_language(language, "command"),
        "sql": get_sinks_for_language(language, "sql"),
        "eval": get_sinks_for_language(language, "eval"),
        "file": get_sinks_for_language(language, "file"),
        "network": get_sinks_for_language(language, "network"),
        "deserialization": get_sinks_for_language(language, "deserialization"),
    }


def get_sanitizers_for_language(language: str) -> Set[str]:
    """Get sanitizer patterns for a language."""
    lang = language.lower()
    if lang in ("typescript", "tsx"):
        lang = "javascript"
    elif lang == "c_sharp":
        lang = "csharp"
    
    return TAINT_PATTERNS.SANITIZERS.get(lang, set())


def is_sink(func_name: str, language: str) -> Dict[str, bool]:
    """Check if a function name is a sink and return which categories.
    
    Returns:
        Dict mapping category to bool (True if func_name is a sink for that category)
    """
    all_sinks = get_all_sinks_for_language(language)
    result = {}
    
    for category, sinks in all_sinks.items():
        # Check exact match or partial match (for method calls)
        is_match = False
        for sink in sinks:
            if func_name == sink or func_name.endswith(f".{sink}") or sink in func_name:
                is_match = True
                break
        result[category] = is_match
    
    return result
