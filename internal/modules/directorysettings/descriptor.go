package directorysettings

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Access-mask bits that let a principal add or change records in a DNS zone.
const (
	rightCreateChild  uint32 = 0x00000001
	rightDeleteChild  uint32 = 0x00000002
	rightWriteProp    uint32 = 0x00000020
	rightDelete       uint32 = 0x00010000
	rightWriteDACL    uint32 = 0x00040000
	rightWriteOwner   uint32 = 0x00080000
	rightGenericAll   uint32 = 0x10000000
	rightGenericWrite uint32 = 0x40000000
	rightFullControl  uint32 = 0x000F01FF
)

// dnsNodeClass is the schemaIDGUID of the dnsNode class. A CreateChild ACE
// scoped to it lets the principal add DNS records.
const dnsNodeClass = "e0fa1e8c-9b45-11d0-afdd-00c04fd930c9"

// ACE is one access-control entry of a DACL, reduced to what the analysis
// needs. Rights names only the write-capable rights the mask grants.
type ACE struct {
	SID        string   `json:"sid"`
	Name       string   `json:"name,omitempty"`
	Allow      bool     `json:"allow"`
	Rights     []string `json:"rights"`
	Mask       uint32   `json:"mask"`
	ObjectType string   `json:"object_type,omitempty"`
	Inherited  bool     `json:"inherited"`
}

// parseDACL reads the DACL of a self-relative SECURITY_DESCRIPTOR and returns
// its allow and deny entries that grant write-capable rights. Entries with
// only read rights are dropped.
func parseDACL(descriptor []byte) ([]ACE, error) {
	if len(descriptor) < 20 {
		return nil, fmt.Errorf("security descriptor is %d bytes", len(descriptor))
	}
	offset := int(binary.LittleEndian.Uint32(descriptor[16:20]))
	if offset == 0 {
		return nil, nil // no DACL: the zone grants everything, reported by the caller
	}
	if offset+8 > len(descriptor) {
		return nil, fmt.Errorf("DACL offset %d is outside the descriptor", offset)
	}
	count := int(binary.LittleEndian.Uint16(descriptor[offset+4 : offset+6]))
	position := offset + 8
	var result []ACE
	for index := 0; index < count; index++ {
		if position+4 > len(descriptor) {
			return result, fmt.Errorf("ACE %d header is truncated", index)
		}
		aceType := descriptor[position]
		flags := descriptor[position+1]
		size := int(binary.LittleEndian.Uint16(descriptor[position+2 : position+4]))
		if size < 8 || position+size > len(descriptor) {
			return result, fmt.Errorf("ACE %d has invalid size %d", index, size)
		}
		body := descriptor[position+4 : position+size]
		position += size

		var (
			allow      bool
			objectType string
			sidBytes   []byte
		)
		mask := binary.LittleEndian.Uint32(body[0:4])
		switch aceType {
		case 0x00, 0x01: // ACCESS_ALLOWED, ACCESS_DENIED
			allow = aceType == 0x00
			sidBytes = body[4:]
		case 0x05, 0x06: // ACCESS_ALLOWED_OBJECT, ACCESS_DENIED_OBJECT
			allow = aceType == 0x05
			if len(body) < 8 {
				continue
			}
			objectFlags := binary.LittleEndian.Uint32(body[4:8])
			cursor := 8
			if objectFlags&0x1 != 0 {
				if len(body) < cursor+16 {
					continue
				}
				objectType = formatGUID(body[cursor : cursor+16])
				cursor += 16
			}
			if objectFlags&0x2 != 0 {
				cursor += 16
			}
			if len(body) < cursor {
				continue
			}
			sidBytes = body[cursor:]
		default:
			continue
		}
		sid, err := formatSID(sidBytes)
		if err != nil {
			continue
		}
		rights := writeRights(mask, objectType)
		if len(rights) == 0 {
			continue
		}
		result = append(result, ACE{SID: sid, Allow: allow, Rights: rights, Mask: mask, ObjectType: objectType, Inherited: flags&0x10 != 0})
	}
	return result, nil
}

// writeRights names the write-capable rights in an access mask. A
// CreateChild limited to another object class does not create DNS records
// and is left out.
func writeRights(mask uint32, objectType string) []string {
	var rights []string
	if mask&rightFullControl == rightFullControl || mask&rightGenericAll != 0 {
		return []string{"GenericAll"}
	}
	if mask&rightGenericWrite != 0 {
		rights = append(rights, "GenericWrite")
	}
	if mask&rightWriteDACL != 0 {
		rights = append(rights, "WriteDacl")
	}
	if mask&rightWriteOwner != 0 {
		rights = append(rights, "WriteOwner")
	}
	if mask&rightCreateChild != 0 && (objectType == "" || strings.EqualFold(objectType, dnsNodeClass)) {
		rights = append(rights, "CreateChild")
	}
	if mask&rightWriteProp != 0 && objectType == "" {
		rights = append(rights, "WriteProperty")
	}
	if mask&(rightDeleteChild|rightDelete) != 0 && objectType == "" {
		rights = append(rights, "Delete")
	}
	return rights
}

// formatSID renders a binary SID as S-1-....
func formatSID(raw []byte) (string, error) {
	if len(raw) < 8 {
		return "", fmt.Errorf("SID is %d bytes", len(raw))
	}
	count := int(raw[1])
	if len(raw) < 8+4*count {
		return "", fmt.Errorf("SID declares %d sub-authorities in %d bytes", count, len(raw))
	}
	var authority uint64
	for _, b := range raw[2:8] {
		authority = authority<<8 | uint64(b)
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "S-%d-%d", raw[0], authority)
	for index := 0; index < count; index++ {
		fmt.Fprintf(&builder, "-%d", binary.LittleEndian.Uint32(raw[8+4*index:12+4*index]))
	}
	return builder.String(), nil
}

// formatGUID renders a 16-byte Windows GUID in its canonical text form.
func formatGUID(raw []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(raw[0:4]), binary.LittleEndian.Uint16(raw[4:6]), binary.LittleEndian.Uint16(raw[6:8]), raw[8:10], raw[10:16])
}

// sidFilterValue escapes a SID string as a binary objectSid filter value.
func sidFilterValue(sid string) (string, bool) {
	parts := strings.Split(sid, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return "", false
	}
	var revision, authority uint64
	if _, err := fmt.Sscan(parts[1], &revision); err != nil {
		return "", false
	}
	if _, err := fmt.Sscan(parts[2], &authority); err != nil {
		return "", false
	}
	sub := parts[3:]
	raw := []byte{byte(revision), byte(len(sub))}
	for shift := 40; shift >= 0; shift -= 8 {
		raw = append(raw, byte(authority>>uint(shift)))
	}
	for _, value := range sub {
		var number uint64
		if _, err := fmt.Sscan(value, &number); err != nil {
			return "", false
		}
		raw = binary.LittleEndian.AppendUint32(raw, uint32(number))
	}
	var builder strings.Builder
	for _, b := range raw {
		fmt.Fprintf(&builder, "\\%02x", b)
	}
	return builder.String(), true
}
