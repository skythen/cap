// Package cap implements the parsing of Java Card converted applets (CAP) and providing them in an installable format.
package cap

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"strings"

	"github.com/pkg/errors"
)

const (
	ComponentHeader            = 1  // ComponentHeader is the tag of the Header component.
	ComponentDirectory         = 2  // ComponentDirectory is the tag of the Directory component.
	ComponentApplet            = 3  // ComponentApplet is the tag of the Applet component.
	ComponentImport            = 4  // ComponentImport is the tag of the Import component.
	ComponentConstantPool      = 5  // ComponentConstantPool is the tag of the ConstantPool component.
	ComponentClass             = 6  // ComponentClass is the tag of the Class component.
	ComponentMethod            = 7  // ComponentMethod is the tag of the Method component.
	ComponentStaticField       = 8  // ComponentStaticField is the tag of the StaticField component.
	ComponentReferenceLocation = 9  // ComponentReferenceLocation is the tag of the ReferenceLocation component.
	ComponentExport            = 10 // ComponentExport is the tag of the Export component.
	ComponentDescriptor        = 11 // ComponentDescriptor is the tag of the Descriptor component.
	ComponentDebug             = 12 // ComponentDebug is the tag of the Debug component.
)

var (
	// jcFrameworkAid is the AID of the JavaCard Framework package.
	jcFrameworkAid = []byte{0xA0, 0x00, 0x00, 0x00, 0x62, 0x01, 0x01}
	// gpApiAid is the AID of the GlobalPlatform Card API package.
	gpApiAid = []byte{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00}
	// formatMagicNumber is a Magic Number that indicates the JavaCard Cap File Format.
	formatMagicNumber = []byte{0xDE, 0xCA, 0xFF, 0xED}
)

var installationOrder = []int{
	ComponentHeader,
	ComponentDirectory,
	ComponentImport,
	ComponentApplet,
	ComponentClass,
	ComponentMethod,
	ComponentStaticField,
	ComponentExport,
	ComponentConstantPool,
	ComponentReferenceLocation,
	ComponentDescriptor,
}

const (
	flagInt    byte = 0x01 // flagInt is the ACC_INT flag and has the value of one if the Java int type is used in this package.
	flagExport byte = 0x02 // flagExport is the ACC_EXPORT flag and has the value of one if an Export Component is included in this CAP file, otherwise 0.
	flagApplet byte = 0x04 // flagApplet is the ACC_APPLET flag and has the value of one if an Applet Component is included in this CAP file, otherwise 0.
)

// Component is the general format of a CAP file component.
type Component struct {
	Tag  uint8  // Tag indicates the kind of component.
	Size uint16 // Size indicates the number of bytes in the info field of the component, not including tag and size.
	Info []byte // Info and its contents vary with the type of component.
}

// parseComponent parses a TLV encoded Component from bytes.
func parseComponent(b []byte) (*Component, error) {
	if len(b) < 3 {
		return nil, errors.New("component does not contain tag (1B) and size (2B)")
	}

	if b[0] > 12 {
		return nil, errors.New("invalid value for tag, must be in range 1-12")
	}

	val := make([]byte, 0, len(b)-3)
	val = append(val, b[3:]...)

	return &Component{
		Tag:  b[0],
		Size: binary.BigEndian.Uint16([]byte{b[1], b[2]}),
		Info: val,
	}, nil
}

// Bytes encodes a Component as TLV encoded bytes.
func (c *Component) Bytes() []byte {
	b := make([]byte, 0, 3+len(c.Info))
	b = append(b, []byte{c.Tag, (byte)(c.Size>>8) & 0xFF, (byte)(c.Size & 0xFF)}...)
	b = append(b, c.Info...)

	return b
}

// MMVersion is a version that consists of a major and minor version number.
type MMVersion struct {
	Major uint8
	Minor uint8
}

// Package is a JavaCard package identified by an AID with a version.
type Package struct {
	// The minor_version and major_version items are the minor and major version numbers of this package.
	// These values uniquely identify the particular implementation of this package and indicate the binary
	//compatibility between packages.
	Version MMVersion
	// The AID represents the Java Card platform name of the package.
	AID []byte
}

// CAP is a Converted Applet that contains a package with optional applets that can
// be loaded onto a JavaCard.
type CAP struct {
	Header           Header             // Header is the representation of the Header component.
	Imports          []Package          // Imports is a list of imported packages contained in the the Import component.
	Applets          [][]byte           // Applets is a list of AIDs of applets that are contained in the Applet component.
	JavaCardVersion  MMPVersion         // JavaCardVersion is the targeted JavaCard Version of the CAP.
	GPCardAPIVersion *MMVersion         // Optional imported GlobalPlatform Card API Version.
	components       map[int]*Component // components is a list of components contained in the cap-file.
}

// Parse takes a pointer to zip.Reader for a '.cap' file, reads its contents and parses its
// cap components and returns a CAP.
func Parse(reader *zip.Reader) (*CAP, error) {
	if reader == nil {
		return nil, errors.New("cap.Parse - nil pointer to zip.Reader")
	}

	var (
		header    *Header
		applets   [][]byte
		imports   []Package
		jcVersion MMPVersion
		gpVersion *MMVersion
	)

	components := make(map[int]*Component, 12)

	// iterate over files in zip and look for cap-Files
	for _, f := range reader.File {
		if strings.HasSuffix(f.Name, ".cap") && len(components) < 12 {
			content, err := readZipFileContentToBytes(f)
			if err != nil {
				return nil, errors.Wrap(err, "cap.Parse - unable to read file contents of "+f.Name)
			}

			component, err := parseComponent(content)
			if err != nil {
				return nil, errors.Wrap(err, "cap.Parse - invalid component in "+f.Name)
			}

			switch component.Tag {
			case ComponentHeader:
				header, err = parseHeaderInfo(component.Info)
				if err != nil {
					return nil, errors.Wrap(err, "cap.Parse - invalid header")
				}
			case ComponentApplet:
				applets, err = parseAppletInfo(component.Info)
				if err != nil {
					return nil, errors.Wrap(err, "cap.Parse -invalid applet")
				}
			case ComponentImport:
				imports, err = parseImportInfo(component.Info)
				if err != nil {
					return nil, errors.Wrap(err, "cap.Parse - invalid import")
				}
				jcVersion = inferJCVersion(imports)
				gpVersion = findGPApiVersion(imports)
			}

			tag, ok := components[int(component.Tag)]
			if ok {
				return nil, errors.Errorf("cap.Parse - component with tag %d is contained more than once", tag)
			}

			components[int(component.Tag)] = component
		}
	}

	return &CAP{
		Header:           *header,
		Applets:          applets,
		Imports:          imports,
		components:       components,
		JavaCardVersion:  jcVersion,
		GPCardAPIVersion: gpVersion,
	}, nil
}

// The Header Component contains general information about this CAP file and the package it defines.
type Header struct {
	// The minor_version and major_version items are the minor and major version numbers of this CAP file.
	CapFileVersion MMVersion
	// Indicates if the Java int type is used in this package.
	UsesInteger bool
	// Indicates if a CAP file contains an Export Component.
	ContainsExport bool
	// Indicates if a CAP file contains an Applet Component.
	ContainsApplet bool
	// Package describes the package defined in this CAP file.
	Package Package
	// Optional name of the package defined in this CAP file.
	PackageName string
}

// parseHeaderInfo parses the byte encoded 'info' of the Header component of a CAP file
// and returns a Header.
func parseHeaderInfo(b []byte) (*Header, error) {
	var header Header

	if len(b) < 13 {
		return nil, errors.Errorf("insufficient length of header, expected minimum: 13, got: %d", len(b))
	}

	if !bytes.Equal(b[:4], formatMagicNumber) {
		return nil, errors.Errorf("does not contain magic number %02X for CAP file format", formatMagicNumber)
	}

	header.CapFileVersion = MMVersion{Major: b[5], Minor: b[4]}

	if b[6]&flagInt == flagInt {
		header.UsesInteger = true
	}

	if b[6]&flagExport == flagExport {
		header.ContainsExport = true
	}

	if b[6]&flagApplet == flagApplet {
		header.ContainsApplet = true
	}

	p, read, err := parsePackageInfo(b[7:])
	if err != nil {
		return nil, errors.Wrap(err, "invalid package")
	}

	header.Package = *p

	nameInfoIndex := 7 + read

	if nameInfoIndex > len(b) {
		return nil, errors.New("offset for package name is out of bounds")
	}

	// check if package name is present
	// The value of this item may be zero if and only if the package does not define any remote interfaces or remote classes.
	if !(nameInfoIndex >= len(b)-1) {
		if nameInfoIndex+int(b[nameInfoIndex]) > len(b) {
			return nil, errors.Errorf("indicated length of name is out of bounds")
		}

		header.PackageName = string(b[nameInfoIndex+1:])
	}

	return &header, nil
}

// parsePackageInfo parses a byte encoded 'package_info' and returns a Package as well as the number of bytes read.
func parsePackageInfo(b []byte) (*Package, int, error) {
	if len(b) < 8 {
		return nil, 0, errors.Errorf("invalid package info length - expected minimum 8, got: %d", len(b))
	}

	lenAid := int(b[2])

	if (3 + lenAid) > len(b) {
		return nil, 0, errors.Errorf("indicated length of AID is out of bounds")
	}

	if lenAid < 5 || lenAid > 16 {
		return nil, 0, errors.Errorf("invalid AID length - must be 5-16 bytes, got: %d", lenAid)
	}

	aid := make([]byte, 0, lenAid)
	aid = append(aid, b[3:3+lenAid]...)

	return &Package{
		Version: MMVersion{Major: b[1], Minor: b[0]},
		AID:     aid,
	}, 3 + lenAid, nil
}

// parseAppletInfo parses the byte encoded 'info' of the Applet component of a CAP file
// and returns the contained AIDs.
func parseAppletInfo(b []byte) ([][]byte, error) {
	if len(b) == 0 {
		return nil, nil
	}

	applets := make([][]byte, 0, b[0])
	off := 1

	for appletCount := b[0]; appletCount > 0; appletCount-- {
		lenAid := int(b[off])
		off++

		if (off + lenAid) > len(b) {
			return nil, errors.Errorf("indicated length of AID is out of bounds")
		}

		id := b[off : off+lenAid]

		if lenAid < 5 || lenAid > 16 {
			return nil, errors.Errorf("invalid AID length - must be 5-16 bytes, got: %d", len(id))
		}

		applets = append(applets, id)
		off += lenAid
		off += 2 // skip install method offset
	}

	return applets, nil
}

// parseImportInfo parses the byte encoded 'info' of the Import component of a CAP file
// and returns the imported packages.
func parseImportInfo(b []byte) ([]Package, error) {
	if len(b) == 0 {
		return nil, nil
	}

	imports := make([]Package, 0, b[0])
	off := 1

	for importCount := b[0]; importCount > 0; importCount-- {
		pi, num, err := parsePackageInfo(b[off:])
		if err != nil {
			return nil, errors.Wrap(err, "invalid package info")
		}

		imports = append(imports, *pi)
		off += num
	}

	return imports, nil
}

// readZipFileContentToBytes reads the contents of a zip.File
// into a byte buffer and returns the result.
func readZipFileContentToBytes(f *zip.File) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	rc, err := f.Open()
	if err != nil {
		return nil, err
	}

	defer func() { _ = rc.Close() }()

	_, err = io.CopyN(buf, rc, int64(f.UncompressedSize64))
	if err != nil {
		return nil, errors.Wrap(err, "copy contents of zip file to buffer")
	}

	err = rc.Close()
	if err != nil {
		return nil, errors.Wrap(err, "close zip file read closer")
	}

	return buf.Bytes(), nil
}

// LoadBytes returns the loadable form of a CAP file.
// It encodes the contained components (tag, size, info) as bytes and returns the appended results.
func (cap *CAP) LoadBytes(includeDescriptor bool) []byte {
	b := make([]byte, 0, cap.loadDataLength(includeDescriptor))

	for _, tag := range installationOrder {
		if tag == ComponentDescriptor && !includeDescriptor {
			continue
		}

		component, ok := cap.components[tag]
		if ok {
			b = append(b, component.Bytes()...)
		}
	}

	return b
}

// loadDataLength returns the length of the CAP in its loadable form in bytes.
func (cap *CAP) loadDataLength(includeDescriptor bool) int {
	var l int

	for _, comp := range cap.components {
		if comp.Tag == ComponentDebug || comp.Tag == ComponentDescriptor && !includeDescriptor {
			continue
		}

		l += int(comp.Size)
		l += 3 // include tag and size itself
	}

	return l
}

// MMPVersion is a version that consists of a major, minor and version number.
type MMPVersion struct {
	Major uint8
	Minor uint8
	Patch uint8
}

// inferJCVersion derives the targeted JavaCard version of a Package based on
// the version of the javacard.framework package it imports.
func inferJCVersion(imports []Package) MMPVersion {
	for _, imp := range imports {
		// search for the javacard.framework package and evaluate the minor version
		if bytes.Equal(imp.AID, jcFrameworkAid) {
			if imp.Version.Major != 1 {
				return MMPVersion{}
			}

			switch imp.Version.Minor {
			case 0:
				return MMPVersion{
					Major: 2,
					Minor: 1,
					Patch: 1,
				}
			case 1:
				return MMPVersion{
					Major: 2,
					Minor: 1,
					Patch: 2,
				}
			case 2:
				return MMPVersion{
					Major: 2,
					Minor: 2,
					Patch: 1,
				}
			case 3:
				return MMPVersion{
					Major: 2,
					Minor: 2,
					Patch: 2,
				}
			case 4:
				return MMPVersion{
					Major: 3,
					Minor: 0,
					Patch: 1,
				}
			case 5:
				return MMPVersion{
					Major: 3,
					Minor: 0,
					Patch: 4,
				}
			case 6:
				return MMPVersion{
					Major: 3,
					Minor: 0,
					Patch: 5,
				}
			case 8:
				return MMPVersion{
					Major: 3,
					Minor: 1,
					Patch: 0,
				}
			}
		}
	}

	return MMPVersion{}
}

// findGPApiVersion searches for an import of the org.globalplatform package and returns the imported
// package version.
func findGPApiVersion(imports []Package) *MMVersion {
	for _, imp := range imports {
		// GP API version correlates to package version
		if bytes.Equal(imp.AID, gpApiAid) {
			return &imp.Version
		}
	}

	return nil
}
