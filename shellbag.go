package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os/user"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type shellbag struct {
	userToQuery string
	userSID     string

	treeNameToPrefixStringMap map[string]string
	prefixStringToTreeNameMap map[string]string
	drivePrefixS              string

	mruRelativePath    string
	mruFullPath        string
	myComputerTreePath string
	documentsTreePath  string

	currentKeyH        *registry.Key
	bagMRUKeyH         *registry.Key
	myComputerTreeKeyH *registry.Key
	documentsTreeKeyH  *registry.Key
}

func initShellbag() *shellbag {
	bag := shellbag{mruRelativePath: "SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"}

	bag.treeNameToPrefixStringMap = map[string]string{
		"MyComputer":   "14001f50e04fd020",
		"Documents":    "3a002e80922b16d3",
		"Pictures":     "3a002e80d43aad24",
		"Downloads":    "3a002e8005398e08",
		"UnMappedGUID": "3a002e8030c09178",
	}

	bag.prefixStringToTreeNameMap = map[string]string{
		"14001f50e04fd020": "MyComputer",
		"3a002e80922b16d3": "Documents",
		"3a002e80d43aad24": "Pictures",
		"3a002e8005398e08": "Downloads",
		"3a002e8030c09178": "UnMappedGUID",
	}

	bag.userToQuery = ""
	bag.drivePrefixS = "19002f"

	return &bag
}

func (b *shellbag) getUserToQuery() {
	var entry string
	fmt.Print("Enter desired usename: ")
	fmt.Scanln(&entry)
	entry = strings.TrimSpace(entry)
	b.userToQuery = entry
}

func (b *shellbag) getSidForUser() {
	if b.userToQuery == "" {
		log.Fatalln("Found no user to query; please provide a valid username")
	}
	u, err := user.Lookup(b.userToQuery)
	if err != nil {
		log.Fatalln("Username does not exist")
	}
	b.userSID = u.Uid
	b.mruFullPath = u.Uid + "\\" + b.mruRelativePath
}

func (b *shellbag) openKeyHandleByPath(path string) {
	k, err := registry.OpenKey(registry.USERS, path, registry.READ)
	if err != nil {
		log.Fatalln("failed to open desired registry key")
	}
	b.currentKeyH = &k
}

func (b *shellbag) findTreeByPrefix(keyToSearch *registry.Key,
	prefix string, pathToSearch string, pathToFind *string) {
	vals, err := keyToSearch.ReadValueNames(0)
	if err != nil {
		log.Fatalf("%s\n", err.Error())
	}
	for _, x := range vals {
		var buf []byte
		buf, _, err := keyToSearch.GetBinaryValue(x)
		if err != nil {
			continue
		}
		p, _ := hex.DecodeString(prefix)
		if bytes.HasPrefix(buf, p) {
			*pathToFind = pathToSearch + "\\" + x
			b.openKeyHandleByPath(*pathToFind)
			return
		}
	}
	log.Fatalf("failed to locate registry tree below %s\n", pathToSearch)
}

func (b *shellbag) queryTree(key *registry.Key, keyPath string) {
	vals, err := key.ReadValueNames(0)
	if err != nil {
		log.Fatalf("%s\n", err.Error())
	}
	for _, x := range vals {
		buf, _, err := key.GetBinaryValue(x)
		if err != nil {
			continue
		}
		if entry, ok := b.prefixStringToTreeNameMap[hex.EncodeToString(buf[:8])]; ok {
			fmt.Printf("%s tree found at %s\\%s\n", entry, keyPath, x)
		} else if hex.EncodeToString(buf[:3]) == b.drivePrefixS {
			fmt.Printf("%s drive found at %s\\%s\n", string(buf[3]), keyPath, x)
		}
	}
}

func main() {
	bag := initShellbag()
	bag.getUserToQuery()
	bag.getSidForUser()
	bag.openKeyHandleByPath(bag.mruFullPath)
	bag.bagMRUKeyH = bag.currentKeyH

	bag.findTreeByPrefix(bag.bagMRUKeyH, bag.treeNameToPrefixStringMap["MyComputer"],
		bag.mruFullPath, &bag.myComputerTreePath)
	bag.myComputerTreeKeyH = bag.currentKeyH
	bag.bagMRUKeyH.Close()
	defer bag.myComputerTreeKeyH.Close()

	bag.queryTree(bag.myComputerTreeKeyH, bag.myComputerTreePath)

}
