package checksec

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/slimm609/checksec/v3/pkg/output"
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
		output.Fatalf("Error opening ELF file: %v", err)
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

			bo := file.ByteOrder
			if file.Class == elf.ELFCLASS64 {
				for i := 0; i < len(data); i += 16 { // Each entry is typically 16 bytes
					if i+16 > len(data) {
						break
					}
					if elf.DynTag(bo.Uint64(data[i:i+8])) == tag {
						value := bo.Uint64(data[i+8 : i+16])
						return append(res, value), err
					}
				}
			} else {
				for i := 0; i < len(data); i += 8 { // Each entry is typically 8 bytes
					if i+8 > len(data) {
						break
					}
					if elf.DynTag(bo.Uint32(data[i:i+4])) == tag {
						value := uint64(bo.Uint32(data[i+4 : i+8]))
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

	fileInfo, statErr := file.Stat()
	if statErr != nil {
		return functions, statErr
	}
	if fileInfo.Size() <= 0 {
		return functions, fmt.Errorf("invalid file size: %d", fileInfo.Size())
	}
	fileSize := uint64(fileInfo.Size())

	f, err := elf.NewFile(file)
	if err != nil {
		fmt.Println("Error parsing ELF file:", err)
		return functions, err
	}

	symTabOffset, _ := DynValueFromPTDynamic(f, elf.DT_SYMTAB)
	strTabOffset, _ := DynValueFromPTDynamic(f, elf.DT_STRTAB)
	strTabSize, _ := DynValueFromPTDynamic(f, elf.DT_STRSZ)
	symEntSizeVals, _ := DynValueFromPTDynamic(f, elf.DT_SYMENT)

	if symTabOffset == nil || strTabSize == nil || strTabOffset == nil {
		return functions, err
	}
	if len(symTabOffset) == 0 || len(strTabOffset) == 0 || len(strTabSize) == 0 {
		return functions, err
	}
	if symTabOffset[0] >= fileSize || strTabOffset[0] >= fileSize {
		return functions, fmt.Errorf("invalid dynamic offsets: symtab=%d strtab=%d fileSize=%d", symTabOffset[0], strTabOffset[0], fileSize)
	}

	// Determine symbol entry size from DT_SYMENT or fallback to arch defaults
	var symEntSize uint64
	if len(symEntSizeVals) > 0 && symEntSizeVals[0] > 0 {
		symEntSize = symEntSizeVals[0]
	} else if f.Class == elf.ELFCLASS32 {
		symEntSize = uint64(binary.Size(elf.Sym32{}))
	} else {
		symEntSize = uint64(binary.Size(elf.Sym64{}))
	}

	if symEntSize == 0 {
		return functions, err
	}

	// Estimate symbol table size conservatively to avoid huge allocations.
	var symTableSize uint64
	if strTabOffset[0] > symTabOffset[0] {
		symTableSize = strTabOffset[0] - symTabOffset[0]
	} else {
		estCount := strTabSize[0] / symEntSize
		symTableSize = estCount * symEntSize
	}

	if symTableSize == 0 {
		return functions, err
	}

	// Cap reads to the underlying file size to avoid huge allocations on malformed binaries.
	if max := fileSize - symTabOffset[0]; symTableSize > max {
		symTableSize = max
	}
	if symTableSize == 0 {
		return functions, err
	}
	if max := fileSize - strTabOffset[0]; strTabSize[0] > max {
		strTabSize[0] = max
	}
	if strTabSize[0] == 0 {
		return functions, err
	}

	// Read the symbol table
	symData := make([]byte, symTableSize)
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

	bo := f.ByteOrder

	// Iterate over the symbol table to extract function names
	for i := 0; i < len(symData); i += symSize {
		if i+symSize > len(symData) {
			break
		}
		if is64Bit {
			sym := elf.Sym64{}
			err := binary.Read(bytes.NewReader(symData[i:i+symSize]), bo, &sym)
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
			err := binary.Read(bytes.NewReader(symData[i:i+symSize]), bo, &sym)
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
