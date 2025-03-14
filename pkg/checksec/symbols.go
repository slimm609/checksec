package checksec

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
)

type symbols struct {
	Output string
	Color  string
}

// SYMBOLS detects usage of elf symbols
func SYMBOLS(name string) *symbols {
	res := symbols{}
	file, err := elf.Open(name)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer file.Close()

	symbols, _ := file.Symbols()
	if len(symbols) == 0 {
		res.Output = "No Symbols"
		res.Color = "green"
	} else {
		res.Output = fmt.Sprintf("%d symbols", len(symbols))
		res.Color = "red"
	}
	return &res
}

func DynValueFromPTDynamic(file *elf.File, tag elf.DynTag) ([]uint64, error) {
	var res []uint64

	for _, prog := range file.Progs {
		if prog.Type == elf.PT_DYNAMIC {
			data := make([]byte, prog.Filesz)
			_, err := prog.ReadAt(data, 0)
			if err != nil {
				fmt.Println("Error reading dynamic section:", err)
				return res, err
			}

			if file.Class == elf.ELFCLASS64 {
				for i := 0; i < len(data); i += 16 { // Each entry is typically 16 bytes
					if i+8 > len(data) {
						break
					}
					if elf.DynTag(binary.LittleEndian.Uint64(data[i : i+8])) == tag {
						value := binary.LittleEndian.Uint64(data[i+8 : i+16])
						return append(res, value), err
					}
				}
			} else {
				for i := 0; i < len(data); i += 8 { // Each entry is typically 8 bytes
					if i+4 > len(data) {
						break
					}
					if elf.DynTag(binary.LittleEndian.Uint32(data[i : i+4])) == tag {
						value := uint64(binary.LittleEndian.Uint32(data[i+4 : i+8]))
						return append(res, value), err
					}
				}
			}
		}
	}
	return res, nil
}

func FunctionsFromSymbolTable(file *os.File) ([]elf.Symbol, error) {
	// Iterate over the dynamic section to handle stripped binaries with no sections
	var functions []elf.Symbol

	f, err := elf.NewFile(file)
	if err != nil {
		fmt.Println("Error parsing ELF file:", err)
		return functions, err
	}

	symTabOffset, _ := DynValueFromPTDynamic(f, elf.DT_SYMTAB)
	strTabOffset, _ := DynValueFromPTDynamic(f, elf.DT_STRTAB)
	strTabSize, _ := DynValueFromPTDynamic(f, elf.DT_STRSZ)

	// Read the symbol table
	symData := make([]byte, symTabOffset[0])
	_, err = file.ReadAt(symData, int64(symTabOffset[0]))
	if err != nil {
		fmt.Println("Error reading symbol table:", err)
		return functions, err
	}

	// Read the string table
	strData := make([]byte, strTabSize[0])
	_, err = file.ReadAt(strData, int64(strTabOffset[0]))
	if err != nil {
		fmt.Println("Error reading string table:", err)
		return functions, err
	}

	// Determine the size of the symbol entry based on architecture
	var symSize int
	var is64Bit bool
	if f.Class == elf.ELFCLASS32 {
		symSize = binary.Size(elf.Sym32{})
		is64Bit = false
	} else {
		symSize = binary.Size(elf.Sym64{})
		is64Bit = true
	}

	// Iterate over the symbol table to extract function names
	for i := 0; i < len(symData); i += symSize {
		if i+symSize > len(symData) {
			break
		}
		if is64Bit {
			sym := elf.Sym64{}
			err := binary.Read(bytes.NewReader(symData[i:i+symSize]), binary.LittleEndian, &sym)
			if err != nil {
				fmt.Println("Error reading symbol:", err)
				continue
			}

			// Check if the symbol is a function
			if elf.STT_FUNC == elf.SymType(sym.Info&0x0F) {
				// Ensure the index is within bounds
				if int(sym.Name) < len(strData) {
					funcName := strData[sym.Name:]
					// Find the end of the string
					endIndex := 0
					for endIndex = 0; endIndex < len(funcName); endIndex++ {
						if funcName[endIndex] == 0 {
							break
						}
					}
					function := elf.Symbol{Name: string(funcName[:endIndex])}
					functions = append(functions, function)
				}
			}
		} else {
			sym := elf.Sym32{}
			err := binary.Read(bytes.NewReader(symData[i:i+symSize]), binary.LittleEndian, &sym)
			if err != nil {
				fmt.Println("Error reading symbol:", err)
				continue
			}

			// Check if the symbol is a function
			if elf.STT_FUNC == elf.SymType(sym.Info&0x0F) {
				// Ensure the index is within bounds
				if int(sym.Name) < len(strData) {
					funcName := strData[sym.Name:]
					// Find the end of the string
					endIndex := 0
					for endIndex = 0; endIndex < len(funcName); endIndex++ {
						if funcName[endIndex] == 0 {
							break
						}
					}
					function := elf.Symbol{Name: string(funcName[:endIndex])}
					functions = append(functions, function)
				}
			}
		}
	}
	return functions, err
}
