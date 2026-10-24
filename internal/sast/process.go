package sast

import (
	"path"
	"strconv"
	"strings"
)

type processVector struct {
	values, texts []taintSet
}

func (r *irRun) evalProcessVector(e *expr, st istate) (taintSet, processVector) {
	var out taintSet
	var vector processVector
	for _, arg := range e.args {
		value := r.eval(arg, st).scalar()
		out = merge(out, value)
		vector.values = append(vector.values, value)
		vector.texts = append(vector.texts, r.sequenceText(arg))
	}
	return out, vector
}

func (r *irRun) checkPythonProcess(c *expr, qname string, literals map[int]processVector, st istate) {
	if r.spec.name != "py" {
		return
	}
	switch qname {
	case "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen":
	default:
		return
	}
	arg := -1
	for i := range c.args {
		kw := ""
		if i < len(c.kw) {
			kw = c.kw[i]
		}
		if kw == "args" || (kw == "" && arg < 0) {
			arg = i
		}
	}
	if arg < 0 {
		return
	}
	vector, literal := literals[arg]
	if !literal {
		name, field, ok := r.pathOf(c.args[arg])
		size, known := st.sequenceSize(name)
		if !ok || field != "" || !known {
			return
		}
		for i := 0; i < size; i++ {
			vector.values = append(vector.values, st.read(name, fieldPart(strconv.Itoa(i))))
			vector.texts = append(vector.texts, st[ikey{name, sequenceTextField(i)}])
		}
	}
	if len(vector.values) < 3 {
		return
	}
	programs := vector.texts[0]
	for i, kw := range c.kw {
		if kw == "executable" {
			programs = r.sequenceText(c.args[i])
		}
	}
	for _, program := range programs {
		family := shellFamily(program.key)
		if family == "" {
			continue
		}
		for i := 1; i+1 < len(vector.values); i++ {
			options := vector.texts[i]
			if len(options) == 0 {
				break
			}
			stop := false
			for _, option := range options {
				if shellCommandFlag(family, option.key) {
					stop = true
					end := i + 2
					if family != "posix" {
						end = len(vector.values)
					}
					for _, value := range vector.values[i+1 : end] {
						for _, at := range value {
							if hit := at.kinds & kCmd; hit != 0 {
								r.reachSink(c.pos, qname+" shell command", hit, at, nil)
							}
						}
					}
				}
				if option.key == "--" || (!strings.HasPrefix(option.key, "-") && !(family == "cmd" && strings.HasPrefix(option.key, "/"))) {
					stop = true
				}
			}
			if stop {
				break
			}
		}
	}
}

func shellFamily(program string) string {
	name := path.Base(strings.ReplaceAll(program, "\\", "/"))
	switch name {
	case "sh", "bash", "dash", "ash", "ksh", "zsh":
		return "posix"
	}
	switch strings.ToLower(name) {
	case "cmd", "cmd.exe":
		return "cmd"
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return "powershell"
	}
	return ""
}

func shellCommandFlag(family, option string) bool {
	switch family {
	case "cmd":
		return strings.EqualFold(option, "/c") || strings.EqualFold(option, "/k")
	case "powershell":
		return strings.EqualFold(option, "-command") || strings.EqualFold(option, "-c")
	case "posix":
		if !strings.HasPrefix(option, "-") || strings.HasPrefix(option, "--") {
			return false
		}
		for _, flag := range option[1:] {
			if flag < 'a' || flag > 'z' {
				return false
			}
		}
		return strings.ContainsRune(option, 'c')
	}
	return false
}
