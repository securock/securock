package sast

// ktSpec is a copy of the Java model. It is made in the last init of the package so that it
// sees every table the other files added to javaSpec, which it shares by reference.
var ktSpec = &langSpec{}

func init() {
	*ktSpec = *javaSpec
	ktSpec.name = "kt"
	frontends["kt"] = &frontend{spec: ktSpec, lower: lowerKotlin}
	// Kotlin's File extensions act on the path they are called on.
	for _, m := range []string{"readText", "readBytes", "readLines", "writeText", "writeBytes", "appendText", "deleteRecursively", "bufferedReader", "inputStream", "outputStream", "forEachLine", "useLines"} {
		ktSpec.sinks["java.io.File."+m] = sink{kind: kPath, args: []int{-1}}
		ktSpec.sinks["java.net.URL."+m] = sink{kind: kSSRF, args: []int{-1}}
	}
	ktSpec.sinks["java.io.File.delete"] = sink{kind: kPath, args: []int{-1}}
	ktSpec.sinks["?.openStream"] = sink{kind: kSSRF, args: []int{-1}}
	ktSpec.misuse["kotlin.random.Random"] = nil
	// Ktor handlers read the request through the implicit "call" receiver.
	ktSpec.sourceRoots = copyRoots(javaSpec.sourceRoots)
	ktSpec.sourceRoots["call"] = map[string]string{"parameters": "request parameter", "queryParameters": "request parameter"}
	ktSpec.sourceMembers = copyStrings(javaSpec.sourceMembers)
	ktSpec.sourceMembers["queryParameters"] = "request parameter"
	ktSpec.sourceMethods = copyStrings(javaSpec.sourceMethods)
	for _, m := range []string{"receiveText", "receiveParameters", "receiveStream", "receiveChannel"} {
		ktSpec.sourceMethods[m] = "request body"
	}
	addBuiltins()
}

func copyStrings(m map[string]string) map[string]string {
	out := make(map[string]string, len(m)+4)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyRoots(m map[string]map[string]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(m)+1)
	for k, v := range m {
		out[k] = copyStrings(v)
	}
	return out
}
