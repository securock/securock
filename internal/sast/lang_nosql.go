package sast

// NoSQL injection, prototype pollution and archive extraction (zip slip).

func init() {
	for _, sp := range []*langSpec{jsSpec, pySpec, javaSpec, phpSpec, rubySpec} {
		if sp.sourcePrefixes == nil {
			sp.sourcePrefixes = map[string]string{}
		}
		if sp.sourceMethods == nil {
			sp.sourceMethods = map[string]string{}
		}
		if sp.sourceRoots == nil {
			sp.sourceRoots = map[string]map[string]string{}
		}
	}
	arch := archiveDesc
	mongoMethods := []string{"find", "findOne", "findOneAndUpdate", "findOneAndDelete", "findOneAndReplace", "updateOne", "updateMany",
		"deleteOne", "deleteMany", "countDocuments", "aggregate", "distinct", "replaceOne", "where", "count", "update", "remove"}
	mongoRecv := []string{"db", "collection", "coll", "col", "mongoose", "mongo", "client", "users", "items", "orders", "posts", "accounts"}

	// ---- JavaScript / TypeScript
	js := jsSpec
	for _, m := range mongoMethods {
		js.sinks["?."+m] = mergeSink(js.sinks["?."+m], sink{kind: kNoSQL, args: []int{0}, recv: mongoRecv, recvUpper: true})
	}
	for _, f := range []string{"merge", "mergeWith", "defaultsDeep", "assignIn"} {
		js.sinks["lodash."+f] = sink{kind: kProto, args: []int{1}, rest: true}
	}
	for _, f := range []string{"set", "setWith", "update", "zipObjectDeep"} {
		js.sinks["lodash."+f] = sink{kind: kProto, args: []int{1}}
	}
	for _, mod := range []string{"lodash/merge", "lodash/mergeWith", "lodash/defaultsDeep", "deepmerge", "merge", "merge-deep", "mixin-deep",
		"defaults-deep", "deep-extend", "just-extend", "object-path", "lodash.merge", "lodash.mergewith", "lodash.defaultsdeep"} {
		js.sinks[mod] = sink{kind: kProto, args: []int{0}, rest: true}
	}
	js.sinks["lodash/set"] = sink{kind: kProto, args: []int{1}}
	js.sinks["lodash.set"] = sink{kind: kProto, args: []int{1}}
	for _, m := range []string{"extend"} {
		js.sinks["?."+m] = sink{kind: kProto, args: []int{1}, rest: true, recv: []string{"$", "jQuery"}}
	}
	js.sanitizers["String"] = kNoSQL | kProto
	js.sanitizers["mongo-sanitize"] = kNoSQL | kNoSQLStr
	js.sanitizers["express-mongo-sanitize"] = kNoSQL | kNoSQLStr
	js.sanitizers["?.toString"] = kNoSQL | kProto
	js.builtins["String"] = true
	js.sourceRoots["entry"] = map[string]string{"fileName": arch, "path": arch, "entryName": arch, "name": arch}
	js.sourceRoots["zipEntry"] = map[string]string{"entryName": arch, "name": arch, "fileName": arch}
	js.sourceRoots["header"] = map[string]string{"name": arch}

	// ---- Python
	py := pySpec
	for _, m := range []string{"find_one", "update_one", "update_many", "delete_one", "delete_many", "count_documents",
		"find_one_and_update", "find_one_and_delete", "find_one_and_replace", "replace_one"} {
		py.sinks["?."+m] = sink{kind: kNoSQL, args: []int{0}}
	}
	for _, m := range []string{"find", "aggregate", "count", "update", "remove", "distinct"} {
		py.sinks["?."+m] = sink{kind: kNoSQL, args: []int{0}, recv: append([]string{"mongo", "collection", "coll", "col"}, mongoRecv...)}
	}
	py.sourceMembers = map[string]string{"filename": arch}
	py.sourceMethods["namelist"] = arch
	py.sourceRoots["member"] = map[string]string{"name": arch}
	py.sourceRoots["tarinfo"] = map[string]string{"name": arch}
	py.sourceRoots["zinfo"] = map[string]string{"filename": arch}
	py.misuse["?.extractall"] = append(py.misuse["?.extractall"], misuse{rule: ruleZipSlip, noKw: "filter",
		detail: "tar members are written wherever their names say, including outside the destination",
		recv:   []string{"tar", "tf", "tarball", "archive", "tar_file", "tarfile", "tar_obj", "t"}})
	py.misuse["shutil.unpack_archive"] = []misuse{{rule: ruleZipSlip, noKw: "filter",
		detail: "tar members are written wherever their names say, including outside the destination"}}

	// ---- Java
	jv := javaSpec
	for _, q := range []string{"org.bson.Document.parse", "com.mongodb.BasicDBObject.parse", "com.mongodb.util.JSON.parse", "org.bson.BsonDocument.parse"} {
		jv.sinks[q] = sink{kind: kNoSQLStr, args: []int{0}}
	}
	// A File is only a path until something opens, deletes or creates it, and the
	// containment check of the usual fix runs between building it and using it.
	for _, m := range []string{"delete", "deleteOnExit", "mkdirs", "mkdir", "createNewFile", "renameTo", "listFiles", "list"} {
		jv.sinks["java.io.File."+m] = sink{kind: kPath, args: []int{-1}}
	}
	jv.sinks["java.nio.file.Paths.get"] = sink{kind: kPath, args: []int{0}, rest: true}
	jv.sinks["java.nio.file.Path.of"] = sink{kind: kPath, args: []int{0}, rest: true}
	jv.sinks["?.resolve"] = sink{kind: kPath, args: []int{0}, recv: []string{"dest", "destDir", "target", "targetDir", "dir", "base", "baseDir", "root", "outDir", "outputDir", "destination", "folder", "path"}}
	for _, e := range []string{
		"java.util.zip.ZipEntry.getName", "org.apache.commons.compress.archivers.zip.ZipArchiveEntry.getName",
		"org.apache.commons.compress.archivers.tar.TarArchiveEntry.getName", "org.apache.commons.compress.archivers.ArchiveEntry.getName",
		"java.util.jar.JarEntry.getName",
	} {
		jv.sourcePrefixes[e] = arch
	}

	// ---- PHP
	ph := phpSpec
	for _, m := range []string{"findOne", "updateOne", "updateMany", "deleteOne", "deleteMany", "countDocuments", "findOneAndUpdate", "findOneAndDelete"} {
		ph.sinks["?."+m] = sink{kind: kNoSQL, args: []int{0}}
	}
	for _, m := range []string{"find", "aggregate"} {
		ph.sinks["?."+m] = sink{kind: kNoSQL, args: []int{0}, recv: mongoRecv}
	}
	ph.sourceMethods["getNameIndex"] = arch

	// ---- Ruby
	rb := rubySpec
	for _, m := range []string{"find", "find_one_and_update", "update_one", "update_many", "delete_one", "delete_many", "aggregate"} {
		rb.sinks["?."+m] = sink{kind: kNoSQL, args: []int{0}, recv: []string{"collection", "coll", "db", "mongo", "users", "client"}}
	}
	rb.sourceRoots["entry"] = map[string]string{"name": arch, "full_name": arch}
	rb.sourceRoots["zip_entry"] = map[string]string{"name": arch}

	addBuiltins()
}

// mergeSink keeps an existing sink for the same key when it is for a different kind of
// problem; the lookup returns one sink per key, so the first definition wins.
func mergeSink(old, add sink) sink {
	if old.kind != 0 {
		return old
	}
	return add
}
