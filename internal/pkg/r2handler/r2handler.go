package r2handler

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arbitraryrw/MobProtID/internal/pkg/utils"

	"github.com/radare/r2pipe-go"
)

var allStringsInBinary map[string][]map[string]string
var allSymbolsInBinary map[string][]map[string]string
var allbinaryInfo map[string]map[string]map[string]string
var allSyscall map[string][]map[string]string
var allBinClassMethFields map[string][]map[string][]map[string]string
var allBinFunctions map[string][]map[string]string

func init() {
	allStringsInBinary = make(map[string][]map[string]string, 0)
	allSymbolsInBinary = make(map[string][]map[string]string, 0)
	allSyscall = make(map[string][]map[string]string, 0)
	allbinaryInfo = make(map[string]map[string]map[string]string, 0)
	allBinClassMethFields = make(map[string][]map[string][]map[string]string, 0)
	allBinFunctions = make(map[string][]map[string]string, 0)
}

// PrepareAnal - gathers all the relevant data required for analysis
func PrepareAnal(binaryPath []string, wg *sync.WaitGroup) {

	defer wg.Done()
	fmt.Println("*** R2 handler Starting ***")

	for index, path := range binaryPath {
		fmt.Println("\tanalysing file ->", index, path)

		strings := make(chan []map[string]string)
		binaryInfo := make(chan map[string]map[string]string)
		symbols := make(chan []map[string]string)
		syscalls := make(chan []map[string]string)
		binClassMethFields := make(chan []map[string][]map[string]string)
		functions := make(chan []map[string]string)

		// fmt.Println(index, path)

		go func(p string) {
			r2Session := openR2Pipe(path)
			binaryInfo <- getBinaryInfo(r2Session)
			r2Session.Close()
		}(path)

		go func(p string) {
			r2Session := openR2Pipe(path)
			strings <- getStringEntireBinary(r2Session)
			r2Session.Close()
		}(path)

		go func(p string) {
			r2Session := openR2Pipe(path)
			symbols <- getSymbols(r2Session)
			r2Session.Close()
		}(path)

		go func(p string) {
			r2sessionMap := openR2Pipe(path)
			syscalls <- getSysCalls(r2sessionMap)
			r2sessionMap.Close()
		}(path)

		go func(p string) {
			r2Session := openR2Pipe(path)
			binClassMethFields <- getClassMethFields(r2Session)
			r2Session.Close()
		}(path)

		go func(p string) {
			r2Session := openR2Pipe(path)
			functions <- getFunctions(r2Session)
			r2Session.Close()
		}(path)

		allStringsInBinary[path] = <-strings
		allSymbolsInBinary[path] = <-symbols
		allSyscall[path] = <-syscalls
		allbinaryInfo[path] = <-binaryInfo
		allBinClassMethFields[path] = <-binClassMethFields
		allBinFunctions[path] = <-functions

		close(strings)
		close(symbols)
		close(syscalls)
		close(binaryInfo)
		close(binClassMethFields)
	}

	// writeString("Letsa go!")

	return
}

func openR2Pipe(path string) r2pipe.Pipe {

	// fmt.Println("Opening", path)
	// r2p, err := r2pipe.NewPipe("malloc://256")
	r2p, err := r2pipe.NewPipe(path)

	if err != nil {
		panic(err)
	}

	return *r2p
}

func writeString(s string, r2session r2pipe.Pipe) {

	_, err := r2session.Cmd("w " + s)
	if err != nil {
		panic(err)
	}
	buf, err := r2session.Cmd("ps")
	if err != nil {
		panic(err)
	}
	fmt.Println(buf)
}

func getStringEntireBinary(r2session r2pipe.Pipe) []map[string]string {

	var buf interface{}

	buf, err := r2session.Cmdj("izzj")

	// Example return of izzj
	//map[length:8 ordinal:86 paddr:6549 section:.shstrtab size:9 string:.comment type:ascii vaddr:245]
	// buf, err := r2session.Cmdj("izzj")

	if err != nil {
		panic(err)
	}

	stringsInBinary := make([]map[string]string, 0)

	// Assert buf as map[string]interface{} and then parse if true
	if buf, ok := buf.([]interface{}); ok {

		for _, stringBundle := range buf {

			/*
				R2 example response:
				map[
					length:22
					ordinal:2131
					paddr:145924
					section:data
					size:23
					string:windowActionBarOverlay
					type:ascii
					vaddr:145924
				]
			*/
			// fmt.Println("[DEBUG] string bundle:", stringBundle)

			if sb, ok := stringBundle.(map[string]interface{}); ok {

				// r2 4.0.0 the "string" key values are b64 encoded
				// sDec, _ := base64.StdEncoding.DecodeString(sb["string"].(string))
				// stringsInBinary = append(stringsInBinary, string(sDec))

				stringMap := make(map[string]string, 0)

				if stringName, ok := sb["string"].(string); ok {
					stringMap["name"] = stringName
				} else {
					panic(
						fmt.Sprintf(
							"[ERROR] Unable to find %q in %q",
							"string",
							sb))
				}

				if stringOffset, ok := sb["paddr"]; ok {
					stringMap["offset"] = fmt.Sprintf("%g", stringOffset)
				} else {
					panic(
						fmt.Sprintf(
							"[ERROR] Unable to find %q in %q",
							"paddr",
							sb))
				}

				stringsInBinary = append(stringsInBinary, stringMap)

			} else {
				panic("Unexpected reponse from R2 while getting all strings in binary!")
			}
		}
	} else {
		fmt.Println("[INFO] Found no strings in binary")
	}

	return stringsInBinary
}

func getBinaryInfo(r2session r2pipe.Pipe) map[string]map[string]string {

	var buf interface{}

	err := utils.Retry(5, 2*time.Second, func() (err error) {
		buf, err = r2session.Cmdj("iIj")
		return
	})

	// buf, err := r2session.Cmdj("iIj")
	if err != nil {
		panic(err)
	}

	binaryInfo := make(map[string]map[string]string)

	if bi, ok := buf.(map[string]interface{}); ok {
		// fmt.Println("R2 returned ->", bi)

		if val, ok := bi["compiler"].(string); ok {

			compBundle := make(map[string]string)
			compBundle["name"] = val
			compBundle["offset"] = "0x0"

			binaryInfo["compiler"] = compBundle
		}

		if val, ok := bi["canary"].(bool); ok {

			canaryBundle := make(map[string]string)
			canaryBundle["name"] = strconv.FormatBool(val)
			canaryBundle["offset"] = "0x0"

			binaryInfo["canary"] = canaryBundle
		}

		if val, ok := bi["pic"].(bool); ok {

			picBundle := make(map[string]string)
			picBundle["name"] = strconv.FormatBool(val)
			picBundle["offset"] = "0x0"

			binaryInfo["pic"] = picBundle
		}

		if val, ok := bi["stripped"].(bool); ok {

			strippedBundle := make(map[string]string)
			strippedBundle["name"] = strconv.FormatBool(val)
			strippedBundle["offset"] = "0x0"

			binaryInfo["stripped"] = strippedBundle
		}

	} else {
		fmt.Println("[ERROR] Response from R2:", buf)
		fmt.Println("[ERROR] Response type from R2:", reflect.TypeOf(buf))
		panic("Unexpected reponse from R2 while getting binary info")
	}

	return binaryInfo
}

func getSymbols(r2session r2pipe.Pipe) []map[string]string {

	var buf interface{}

	// Example data from r2:
	// map[bind:GLOBAL flagname:sym.main is_imported:false name:main
	//ordinal:61 paddr:1706 realname:main size:56 type:FUNC vaddr:1706]
	buf, err := r2session.Cmdj("isj")

	if err != nil {
		panic(err)
	}

	symbolsInBinary := make([]map[string]string, 0)

	if buf, ok := buf.([]interface{}); ok {
		for _, symMap := range buf {

			// fmt.Println(symMap)
			/*
				map[
					bind:GLOBAL
					flagname:sym.Lcom_example_dummyapplication_SensitiveLogic.method.rootDetection__Z
					is_imported:false
					name:Lcom/example/dummyapplication/SensitiveLogic.method.rootDetection()Z
					ordinal:5829
					paddr:79828
					realname:Lcom/example/dummyapplication/SensitiveLogic.method.rootDetection()Z
					size:106
					type:FUNC
					vaddr:79828
				]
			*/

			if sym, ok := symMap.(map[string]interface{}); ok {

				if symType, ok := sym["type"].(string); ok {

					// Can be of type SECT / FILE / FUNC / OBJ / NOTYPE
					if symType == "FUNC" {

						symbolMap := make(map[string]string, 0)

						if symName, ok := sym["realname"].(string); ok {
							symbolMap["name"] = symName
						} else {
							panic(
								fmt.Sprintf(
									"[ERROR] Unable to find %q in %q",
									"realname",
									sym))
						}

						if symOffset, ok := sym["paddr"]; ok {
							symbolMap["offset"] = fmt.Sprintf("%g", symOffset)
						} else {
							panic(
								fmt.Sprintf(
									"[ERROR] Unable to find %q in %q",
									"paddr",
									sym))
						}

						symbolsInBinary = append(symbolsInBinary, symbolMap)
					}
				}
			}
		}
	}

	return symbolsInBinary
}

func getSysCalls(r2session r2pipe.Pipe) []map[string]string {

	var buf string

	err := utils.Retry(5, 2*time.Second, func() (err error) {
		// Annoyingly you can't seem to chain as and /j to get json output
		// having to parse the r2 string response
		buf, err = r2session.Cmd("/as")
		return
	})

	if err != nil {
		panic(err)
	}

	syscallMap := make([]map[string]string, 0)

	if len(buf) > 0 {

		for _, val := range strings.Split(buf, "\n") {

			syscall := make(map[string]string, 0)

			splitVal := strings.Fields(val)

			syscall["name"] = splitVal[1]
			syscall["offset"] = splitVal[0]

			syscallMap = append(syscallMap, syscall)

		}

	}

	return syscallMap
}

func getStringsDataSections(r2session r2pipe.Pipe) {
	_, err := r2session.Cmdj("izj")
	if err != nil {
		panic(err)
	}
}

func getExports(r2session r2pipe.Pipe) {

}

func getFunctions(r2session r2pipe.Pipe) []map[string]string {

	// Instruct r2 to analyse the binary
	r2session.Cmd("aaa")

	buf, err := r2session.Cmdj("aflj")

	if err != nil {
		panic(err)
	}

	functionsInBinary := make([]map[string]string, 0)

	if buf, ok := buf.([]interface{}); ok {
		for _, funcBundle := range buf {

			funBundle := make(map[string]string)

			if fun, ok := funcBundle.(map[string]interface{}); ok {

				// fmt.Println("[DEBUG] r2 func object ->", fun)

				/*
					R2 sample response:
					map[bits:32 bpvars:[] callrefs:[map[addr:399668 at:543028 type:CALL]] cc:1 codexrefs:[map[addr:543248 at:543028 type:CALL]]
					cost:0 datarefs:[] dataxrefs:[] difftype:new ebbs:1 edges:0 indegree:1 is-pure:true maxbound:543036 minbound:543028
					name:method.constructor.Landroid_support_v4_os_ResultReceiver_1.Landroid_support_v4_os_ResultReceiver_1.method._init___V
					nargs:0 nbbs:1 nlocals:0 noreturn:false offset:543028 outdegree:1 realsz:8 regvars:[]
					signature:method.constructor.Landroid_support_v4_os_ResultReceiver_1.Landroid_support_v4_os_ResultReceiver_1.method._init___V ();
					size:8 spvars:[] stackframe:0 type:fcn]
				*/

				if funName, ok := fun["name"].(string); ok {
					funBundle["name"] = funName
				}

				if funOffset, ok := fun["offset"]; ok {
					funBundle["offset"] = fmt.Sprintf("%g", funOffset)
				}

				if funType, ok := fun["type"].(string); ok {
					funBundle["type"] = funType
				}
			}

			// Append the individual function to the parent array
			functionsInBinary = append(functionsInBinary, funBundle)

		}
	}

	return functionsInBinary
}

// Seems to overlap alot with getFunctions() investigate if this has value
func getClassMethFields(r2session r2pipe.Pipe) []map[string][]map[string]string {

	// Map to store all classes, methods, and fields in a structured format
	allObjectsMap := make([]map[string][]map[string]string, 0)

	buf, err := r2session.Cmdj("icj")

	if err != nil {
		panic(err)
	}

	if buf, ok := buf.([]interface{}); ok {

		for _, packedData := range buf {

			if data, ok := packedData.(map[string]interface{}); ok {

				objectCollection := make(map[string][]map[string]string, 0)

				/*
					R2 Sample Response:
					map[
						addr:56908
						classname:Landroidx/appcompat/R$anim
						fields:[
							map[addr:10060 flags:[static public final] name:Landroidx/appcompat/R$anim.sfield_abc_fade_in:I]
							map[addr:10068 flags:[static public final] name:Landroidx/appcompat/R$anim.sfield_abc_fade_out:I]
							map[addr:1007 6 flags:[static public final] name:Landroidx/appcompat/R$anim.sfield_abc_grow_fade_in_from_bottom:I]
							map[addr:10084 flags:[static public final] name:Landroidx/appcompat/R$anim.sfield_abc_popup_enter:I]
							map[addr:10092 flags:[static public final] name:Landroidx/appcompat/R$anim.sfield_abc_popup_exit:I]
							map[addr:10100 flags:[static public final]name:Landroidx/appcompat/R$anim.sfield_abc_shrink_fade_out_from_bottom:I]
							map[addr:10108 flags:[static public final]name:Landroidx/appcompat/R$anim.sfield_abc_slide_in_bottom:I]
							map[addr:10116 flags:[static public final]name:Landroidx/appcompat/R$anim.sfield_abc_slide_in_top:I]
							map[addr:10124 flags:[static public final]name:Landroidx/appcompat/R$anim.sfield_abc_slide_out_bottom:I]
							map[addr:10132 flags:[static public final]name:Landroidx/appcompat/R$anim.sfield_abc_slide_out_top:I]
							map[addr:10140 flags:[static public final]name:Landroidx/appcompat/R$anim.sfield_abc_tooltip_enter:I]
							map[addr:10148 flags:[static public final]name:Landroidx/appcompat/R$anim.sfield_abc_tooltip_exit:I]
						]
						index:0
						methods:[
							map[addr:63452 flags:[private constructor]name:Landroidx/appcompat/R$anim.method.<init>()V]
						]
						super:Ljava/lang/Object; visibility:PUBLIC FINAL
					]
				*/

				if packedFieldData, ok := data["fields"].([]interface{}); ok {

					fieldCollection := make([]map[string]string, 0)

					for _, field := range packedFieldData {

						if f, ok := field.(map[string]interface{}); ok {
							fieldInstance := make(map[string]string, 0)

							if fName, ok := f["name"].(string); ok {
								fieldInstance["name"] = fName
							}

							if addr, ok := f["addr"].(float64); ok {
								fieldInstance["offset"] = fmt.Sprintf("%g", addr)
							}

							fieldCollection = append(fieldCollection, fieldInstance)
						}
					}

					objectCollection["fields"] = fieldCollection
				}

				if packedMethods, ok := data["methods"].([]interface{}); ok {

					methodCollection := make([]map[string]string, 0)

					for _, method := range packedMethods {

						if m, ok := method.(map[string]interface{}); ok {
							methodInstance := make(map[string]string, 0)

							if mName, ok := m["name"].(string); ok {
								methodInstance["name"] = mName
							}

							if addr, ok := m["addr"].(float64); ok {
								methodInstance["offset"] = fmt.Sprintf("%g", addr)
							}

							methodCollection = append(methodCollection, methodInstance)
						}
					}
					objectCollection["methods"] = methodCollection
				}

				// Put into array of maps to make it consistent with methods / fields
				classCollection := make([]map[string]string, 0)
				classInstance := make(map[string]string)

				if cName, ok := data["classname"].(string); ok {
					classInstance["name"] = cName
				}

				if cOffset, ok := data["addr"].(float64); ok {
					classInstance["offset"] = fmt.Sprintf("%g", cOffset)
				}

				classCollection = append(classCollection, classInstance)

				objectCollection["class"] = classCollection

				allObjectsMap = append(allObjectsMap, objectCollection)

				// break
			}
		}
	}

	return allObjectsMap
}
