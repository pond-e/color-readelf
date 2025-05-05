package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Constants for color codes
const (
	BLUE_TEXT    = "\033[0;34m"
	GREEN_TEXT   = "\033[0;32m"
	MAGENTA_TEXT = "\033[0;35m"
	RESET_TEXT   = "\033[0m"
)

type Elf64Ehdr struct {
	Ident     [16]byte
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint64
	Phoff     uint64
	Shoff     uint64
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

type Elf64Phdr struct {
	Type   uint32
	Flags  uint32
	Offset uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

type Elf64Shdr struct {
	Name      uint32
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

type Elf64ShdrWithName struct {
	Name      string
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

// ColorPrint prints the formatted string with color if a substring from the map is found
func ColorPrint(format string, args ...interface{}) {
	buffer := fmt.Sprintf(format, args...)

	// Define color mappings with associated regex patterns
	colorMappings := []struct {
		pattern *regexp.Regexp
		color   string
	}{
		{regexp.MustCompile(`(?i)section`), BLUE_TEXT},
		{regexp.MustCompile(`(?i)program`), GREEN_TEXT},
		{regexp.MustCompile(`(0x[0-9a-f]+)`), MAGENTA_TEXT},
	}

	// Apply each color mapping
	for _, mapping := range colorMappings {
		buffer = mapping.pattern.ReplaceAllStringFunc(buffer, func(s string) string {
			return mapping.color + s + RESET_TEXT
		})
	}

	fmt.Printf("%s", buffer)
}

// PrintELFHeader displays the ELF header information
func PrintELFHeader(ehdr *Elf64Ehdr) {
	ColorPrint("This image displays information about a machine and operating system:\n")
	ColorPrint("  Magic:   ")
	for _, b := range ehdr.Ident {
		ColorPrint("%02x ", b)
	}
	ColorPrint("\n")
	ColorPrint("  Class:                             %d\n", ehdr.Ident[4])
	ColorPrint("  Data:                              %d\n", ehdr.Ident[5])
	ColorPrint("  Version:                           %d\n", ehdr.Ident[6])
	ColorPrint("  OS/ABI:                            %d\n", ehdr.Ident[7])
	ColorPrint("  ABI Version:                       %d\n", ehdr.Ident[8])
	ColorPrint("  Type:                              %d\n", ehdr.Type)
	ColorPrint("  Machine:                           %d\n", ehdr.Machine)
	ColorPrint("  Version:                           0x%x\n", ehdr.Version)
	ColorPrint("  Entry point address:               0x%x\n", ehdr.Entry)
	ColorPrint("  Start of program headers:          %d (bytes into file)\n", ehdr.Phoff)
	ColorPrint("  Start of section headers:          %d (bytes into file)\n", ehdr.Shoff)
	ColorPrint("  Flags:                             0x%x\n", ehdr.Flags)
	ColorPrint("  Size of this header:               %d (bytes)\n", ehdr.Ehsize)
	ColorPrint("  Size of program headers:           %d (bytes)\n", ehdr.Phentsize)
	ColorPrint("  Number of program headers:         %d\n", ehdr.Phnum)
	ColorPrint("  Size of section headers:           %d (bytes)\n", ehdr.Shentsize)
	ColorPrint("  Number of section headers:         %d\n", ehdr.Shnum)
	ColorPrint("  Section header string table index: %d\n", ehdr.Shstrndx)
}

func JSONOutputELFHeader(ehdr *Elf64Ehdr) {
	jsonData, err := json.MarshalIndent(ehdr, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting to JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}

func PrintProgramHeaders(file *os.File, ehdr *Elf64Ehdr) {
	file.Seek(int64(ehdr.Phoff), 0)
	ColorPrint("Program Headers:\n")

	for i := 0; i < int(ehdr.Phnum); i++ {
		var phdr Elf64Phdr
		binary.Read(file, binary.LittleEndian, &phdr)

		ColorPrint("  Type:               %d\n", phdr.Type)
		ColorPrint("  Offset:             0x%x\n", phdr.Offset)
		ColorPrint("  Virtual Address:    0x%x\n", phdr.Vaddr)
		ColorPrint("  Physical Address:   0x%x\n", phdr.Paddr)
		ColorPrint("  File Size:          %d\n", phdr.Filesz)
		ColorPrint("  Memory Size:        %d\n", phdr.Memsz)
		ColorPrint("  Flags:              0x%x\n", phdr.Flags)
		ColorPrint("  Align:              %d\n\n", phdr.Align)
	}
}

func JSONOutputProgramHeaders(file *os.File, ehdr *Elf64Ehdr) {
	file.Seek(int64(ehdr.Phoff), 0)
	var phdrs []Elf64Phdr

	for i := 0; i < int(ehdr.Phnum); i++ {
		var phdr Elf64Phdr
		binary.Read(file, binary.LittleEndian, &phdr)
		phdrs = append(phdrs, phdr)
	}

	jsonData, err := json.MarshalIndent(phdrs, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting program headers to JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}

func dumpStringTable(file *os.File, offset, size uint64) []byte {
	file.Seek(int64(offset), 0)
	strData := make([]byte, size)
	binary.Read(file, binary.LittleEndian, &strData)
	return strData
}

func getString(data []byte, index uint32) string {
	end := index
	for end < uint32(len(data)) && data[end] != 0 {
		end++
	}
	return string(data[index:end])
}

func PrintSectionHeaders(file *os.File, ehdr *Elf64Ehdr) {
	var shdrwns []Elf64ShdrWithName = MakeSectionHeaderWithName(file, ehdr)

	for i := 0; i < int(ehdr.Shnum); i++ {
		ColorPrint("  [%2d] Name:               %s\n", i, shdrwns[i].Name)
		ColorPrint("       Type:               %d\n", shdrwns[i].Type)
		ColorPrint("       Flags:              0x%x\n", shdrwns[i].Flags)
		ColorPrint("       Address:            0x%x\n", shdrwns[i].Addr)
		ColorPrint("       Offset:             0x%x\n", shdrwns[i].Offset)
		ColorPrint("       Size:               %d\n", shdrwns[i].Size)
		ColorPrint("       Link:               %d\n", shdrwns[i].Link)
		ColorPrint("       Info:               %d\n", shdrwns[i].Info)
		ColorPrint("       Address Align:      %d\n", shdrwns[i].Addralign)
		ColorPrint("       Entry Size:         %d\n\n", shdrwns[i].Entsize)
	}
}

func MakeSectionHeaderWithName(file *os.File, ehdr *Elf64Ehdr) []Elf64ShdrWithName {
	file.Seek(int64(ehdr.Shoff), 0)
	ColorPrint("Section Headers:\n")

	// Load section headers into a slice
	shdrs := make([]Elf64Shdr, ehdr.Shnum)
	shdrwns := make([]Elf64ShdrWithName, ehdr.Shnum)
	for i := 0; i < int(ehdr.Shnum); i++ {
		binary.Read(file, binary.LittleEndian, &shdrs[i])
	}

	// Load the section header string table
	stringTable := dumpStringTable(file, shdrs[ehdr.Shstrndx].Offset, shdrs[ehdr.Shstrndx].Size)

	for i := 0; i < int(ehdr.Shnum); i++ {
		sectionName := getString(stringTable, shdrs[i].Name)
		shdrwns[i].Name = sectionName
		shdrwns[i].Type = shdrs[i].Type
		shdrwns[i].Flags = shdrs[i].Flags
		shdrwns[i].Addr = shdrs[i].Addr
		shdrwns[i].Offset = shdrs[i].Offset
		shdrwns[i].Size = shdrs[i].Size
		shdrwns[i].Link = shdrs[i].Link
		shdrwns[i].Info = shdrs[i].Info
		shdrwns[i].Addralign = shdrs[i].Addralign
		shdrwns[i].Entsize = shdrs[i].Entsize
	}

	return shdrwns
}

func JSONOutputSectionHeaders(file *os.File, ehdr *Elf64Ehdr) {
	var shdrwns []Elf64ShdrWithName = MakeSectionHeaderWithName(file, ehdr)

	jsonData, err := json.MarshalIndent(shdrwns, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error converting program headers to JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}

func ReadELFHeader(file *os.File) (*Elf64Ehdr, error) {
	ehdr := new(Elf64Ehdr)
	err := binary.Read(file, binary.LittleEndian, ehdr)
	if err != nil {
		return nil, err
	}
	return ehdr, nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <-h|-l|-S|-j|-jh|-jl|-jS> <elf-file>\n", os.Args[0])
		os.Exit(1)
	}

	option := os.Args[1]
	fileName := os.Args[2]

	file, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	ehdr, err := ReadELFHeader(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading ELF header: %v\n", err)
		os.Exit(1)
	}

	switch option {
	case "-h":
		PrintELFHeader(ehdr)
	case "-l":
		PrintProgramHeaders(file, ehdr)
	case "-S":
		PrintSectionHeaders(file, ehdr)
	case "-jh":
		JSONOutputELFHeader(ehdr)
	case "-jl":
		JSONOutputProgramHeaders(file, ehdr)
	case "-jS":
		JSONOutputSectionHeaders(file, ehdr)
	default:
		fmt.Fprintf(os.Stderr, "Invalid option: %s\n", option)
		os.Exit(1)
	}
}
