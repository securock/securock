package sast

import (
	"bytes"
	"regexp"
)

// The Kotlin grammar has bugs that lose a whole function or file on valid code. Each
// rewrite below keeps every line and, where it can, every column, and changes nothing the
// analysis reads. Run the Kotlin tests after touching one.

// prepareKotlin applies the rewrites in order.
func prepareKotlin(src []byte) []byte {
	return markIndexedAssignments(blankTypeArguments(blankVisibility(blankExtensionAnnotations(blankClassRefs(src)))))
}

var reClassRef = regexp.MustCompile(`::class(\.(javaObjectType|javaPrimitiveType|java|kotlin)\b)?`)

// blankClassRefs overwrites Kotlin class literals (Foo::class) with spaces of the same
// length: the Kotlin grammar rejects `@OptIn(Foo::class)` before an extension function,
// and a class literal carries no data, so positions stay and nothing is lost.
func blankClassRefs(src []byte) []byte {
	return reClassRef.ReplaceAllFunc(src, func(m []byte) []byte { return bytes.Repeat([]byte{' '}, len(m)) })
}

var reExtensionAnnotations = regexp.MustCompile(`(?m)((?:^[ \t]*@[\w.:]+(?:\([^)\n]*\))?[ \t]*\n)+)([ \t]*(?:\w+[ \t]+)*fun[ \t]+(?:<[^>\n]*>[ \t]+)?[\w.<>?, ]+\.\w+[ \t]*[(<])`)

// blankExtensionAnnotations blanks the annotation lines that precede an extension
// function: after another annotated declaration the Kotlin grammar reads the function as
// an anonymous function and loses the rest of the file. Annotations on extension
// functions (@Serializable, @Suppress, @OptIn) carry no request mapping, so nothing the
// analysis uses is lost.
func blankExtensionAnnotations(src []byte) []byte {
	return reExtensionAnnotations.ReplaceAllFunc(src, func(m []byte) []byte {
		sub := reExtensionAnnotations.FindSubmatch(m)
		out := append([]byte(nil), m...)
		for i := range sub[1] {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
		return out
	})
}

var reVisibility = regexp.MustCompile(`(?m)^([ \t]*)(public|private|internal|protected)([ \t]+(?:(?:suspend|inline|operator|infix|tailrec|override|open|final|abstract|external|expect|actual)[ \t]+)+fun[ \t]+(?:<[^>\n]*>[ \t]+)?[\w.<>?, ]+\.\w+[ \t]*[(<])`)

// blankVisibility blanks a visibility modifier that comes before other modifiers on an
// extension function ("internal suspend fun HttpClient.get()"): the Kotlin grammar
// reads the modifiers as identifiers of an infix expression and loses the function.
// Visibility does not matter to the analysis, and the positions stay.
func blankVisibility(src []byte) []byte {
	return reVisibility.ReplaceAllFunc(src, func(m []byte) []byte {
		sub := reVisibility.FindSubmatch(m)
		out := append([]byte(nil), m...)
		for i := len(sub[1]); i < len(sub[1])+len(sub[2]); i++ {
			out[i] = ' '
		}
		return out
	})
}

var reTypeArgs = regexp.MustCompile(`(\w)(<[A-Za-z_][\w.?, <>*]*>)\(`)

// blankTypeArguments blanks the explicit type arguments of a call (jsonSchema<Map<K, V>>(),
// call.receive<User>()): the Kotlin grammar mistakes them for comparisons when the
// arguments continue on the next line. Types do not carry taint, and positions stay.
func blankTypeArguments(src []byte) []byte {
	return reTypeArgs.ReplaceAllFunc(src, func(m []byte) []byte {
		sub := reTypeArgs.FindSubmatch(m)
		out := append([]byte(nil), m...)
		for i := len(sub[1]); i < len(sub[1])+len(sub[2]); i++ {
			out[i] = ' '
		}
		return out
	})
}

var reIndexedAssign = regexp.MustCompile(`(?m)^([ \t]*)([A-Za-z_]\w*)(\[[^\n=]*?\][ \t]*[-+*/%]?=)([^=\n]|$)`)

// markIndexedAssignments writes `a[k] = v` as `a!![k] = v`. The Kotlin grammar fails on a
// second statement of that shape in the same block and loses the rest of the function
// (`model["a"] = x` followed by `model["b"] = y` is the usual case). The two characters
// replace indentation when there is enough, so only the identifier's own column moves.
func markIndexedAssignments(src []byte) []byte {
	return reIndexedAssign.ReplaceAllFunc(src, func(m []byte) []byte {
		sub := reIndexedAssign.FindSubmatch(m)
		indent, name, rest, tail := sub[1], sub[2], sub[3], sub[4]
		if len(indent) >= 2 {
			indent = indent[2:]
		}
		out := append([]byte(nil), indent...)
		out = append(out, name...)
		out = append(out, '!', '!')
		out = append(out, rest...)
		return append(out, tail...)
	})
}
