package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
	"github.com/vishvananda/netlink"
)

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func openRawSock(index int) (int, error) {
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

	ifname := flag.String("name", "ens32", "specify ethernet name")
	flag.Parse()

	var index int
	links, err := netlink.LinkList()
	if err != nil {
		fmt.Println("Error")
	}

	for _, link := range links {
		// newMap[link.Attrs().Index] = link.Attrs().Name

		if link.Attrs().Name == *ifname {
			index = link.Attrs().Index
			fmt.Println("Index is:", link.Attrs().Index)

		}
	}

	mod := elf.NewModule("bpf_prog/filter.o")

	if err := mod.Load(nil); err != nil {
		panic(err)
	}

	sf := mod.SocketFilter("socket1")

	sock, err := openRawSock(index)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(sock)

	if err := elf.AttachSocketFilter(sf, sock); err != nil {
		panic(err)
	}

	myMap := mod.Map("my_map")

	var key uint32 = 6
	var value int64

	for {
		time.Sleep(1 * time.Second)

		mod.LookupElement(myMap, unsafe.Pointer(&key), unsafe.Pointer(&value))
		fmt.Println("The value is: ", value)
	}

}
