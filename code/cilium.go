package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

var bpfprogramFile string = "bpf_prog/filter.o"

// ExampleSocketELF demonstrates how to load an eBPF program from an ELF,
// and attach it to a raw socket.
func Example_socketELF(ifname string) {
	const SO_ATTACH_BPF = 50

	program, err := ioutil.ReadFile(bpfprogramFile)
	if err != nil {
		fmt.Println("Error readinf file into byte slice !")
	}
	// Get intrface ifindex

	var index int
	links, err := netlink.LinkList()
	if err != nil {
		fmt.Println("Error")
	}

	for _, link := range links {
		// newMap[link.Attrs().Index] = link.Attrs().Name

		if link.Attrs().Name == ifname {
			index = link.Attrs().Index
			fmt.Println("Index is:", link.Attrs().Index)

		}
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program))
	if err != nil {
		panic(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	defer coll.Close()

	prog := coll.DetachProgram("filter")
	if prog == nil {
		panic("no program named filter found")
	}
	defer prog.Close()

	sock, err := openRawSock(index)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(sock)

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
		panic(err)
	}

	fmt.Printf("Filtering on eth index: %d\n", index)
	fmt.Println("Packet stats:")

	myMap := coll.DetachMap("my_map")
	if myMap == nil {
		panic(fmt.Errorf("no map named duration_end found"))
	}
	defer myMap.Close()

	var key uint32 = 6
	var value int64

	for {

		time.Sleep(time.Second)

		if err := myMap.Lookup(key, &value); err != nil {
			if strings.Contains(err.Error(), "key does not exist") {
				log.Printf("Key does not exist yet !")
			} else {
				panic(err)
			}
		}

		fmt.Printf("Value: %d\n", value)

	}

}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func openRawSock(index int) (int, error) {
	// const ETH_P_ALL uint16 = 0x00<<8 | 0x03
	const ETH_P_ALL uint16 = 0x03

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = htons(ETH_P_ALL)
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

func main() {
	name := flag.String("name", "ens32", "specify ethernet name")
	flag.Parse()
	if len(flag.Args()) > 0 || name == nil {
		flag.PrintDefaults()
		os.Exit(1)
	}

	Example_socketELF(*name)

}
